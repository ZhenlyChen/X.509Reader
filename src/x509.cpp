#include "x509.h"
using namespace std;

typedef unsigned char byte;

static const string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

typedef struct {
  int len;     // ����
  int lenLen;  // ������ռ�ĳ���
} lenData;     // ������Ϣ

typedef struct {
  string title;
  int len;
  byte* data;
  int type;
} Item;  // ������Ŀ

vector<Item> ansData;

// ���ȡ�����ռ��
lenData getLen(byte* data, int i) {
  lenData res;
  res.lenLen = 1;
  if (data[i] & 0x80) {
    int len_len = data[i] & 0x7f;
    int len = 0;
    i++;
    for (int j = 0; j < len_len; j++) {
      len <<= 8;
      // cout << "+" << ((data[i] & 0xf0) >> 4) << "-" << (data[i] & 0xf) <<
      // endl;
      len += data[i + j];
    }
    res.len = len;
    res.lenLen += len_len;
  } else {
    res.len = data[i] & 0x7f;
  }
  // cout << "debug:" << res.len << "-" << res.lenLen << endl;
  return res;
}

void parseANS(byte* data, int begin, int end) {
  int i = begin;
  lenData lens;
  byte* text;
  int oiFirst;
  int oiIndex;
  string title;
  int type;
  while (i < end) {
    int type = data[i];
    i++;
    lens = getLen(data, i);
    if (i + lens.lenLen <= end) {
      i += lens.lenLen;
    }
    title = "";
    switch (type) {
      case 0x30:  // �ṹ������
        // title = "Sequence";
        // ansData.push_back({title, lens.len, NULL, type});
        parseANS(data, i, i + lens.len);
        break;
      case 0x31:  // Set����
        // title = "Set";
        // ansData.push_back({title, lens.len, NULL, type});
        parseANS(data, i, i + lens.len);
        break;
      case 0xa3:  // ��չ�ֶ�
        title = "Extension";
        ansData.push_back({title, lens.len, NULL, type});
        parseANS(data, i, i + lens.len);
        break;
      case 0xa0:  // ֤��汾
        title = "Version";
        ansData.push_back({title, lens.len, NULL, type});
        parseANS(data, i, i + lens.len);
        break;
      case 0x04:  // OCTET STRING
        // title = "Octet";
        // ansData.push_back({title, lens.len, NULL, type});
        parseANS(data, i, i + lens.len);
      case 0x05:
        break;
      case 0x06:  // Object Identifier
        title = "";
        oiFirst = data[i] & 0x7f;
        oiIndex = min(oiFirst / 40, 2);
        title.append(to_string(min(oiFirst / 40, 2)));
        title.append(".");
        title.append(to_string(oiFirst - 40 * oiIndex));
        title.append(".");
        oiIndex = 2;
        oiFirst = 0;
        for (int t = 1; t < lens.len; t++) {
          oiFirst <<= 7;
          oiFirst += data[i + t] & 0x7f;
          if (!(data[i + t] & 0x80)) {
            title.append(to_string(oiFirst));
            title.append(".");
            oiIndex++;
            oiFirst = 0;
          }
        }
        ansData.push_back(
            {title.substr(0, title.length() - 1), lens.len, NULL, type});
        break;
      case 0x17:  // ʱ���
        title = "UTCTime";
      case 0x13:  // �ַ���
      case 0x82:  // subjectUniqueID
      case 0x16:  // IA5String����
      case 0x86:  // ����IA5String����
        for (int t = 0; t < lens.len; t++) {
          title += (char)data[i + t];
        }
        ansData.push_back({title, lens.len, NULL, type});
        break;
      case 0x01:  // ��������
        oiFirst = 0xff;
        for (int t = 0; t < lens.len; t++) {
          oiFirst &= data[i + t];
        }
        ansData.push_back(
            {oiFirst == 0 ? "False" : "True", lens.len, NULL, type});
        break;
      case 0x02:  // ��������
      case 0x80:  // ֱ�����
        text = new byte[lens.len];
        for (int t = 0; t < lens.len; t++) {
          text[t] = data[i + t];
        }
        ansData.push_back({title, lens.len, text, type});
        break;
      case 0x03:  // Bit String ����
        text = new byte[lens.len - 1];
        for (int t = 0; t < lens.len - 1; t++) {
          text[t] = data[i + t + 1];
        }
        ansData.push_back({"", lens.len - 1, text, type});
        break;
      case 0x00:
        text = new byte[end - i - 1];
        for (int t = i + 1; t < end; t++) {
          text[t - i - 1] = data[t];
        }
        ansData.push_back({"0x00", end - begin - 1, text, type});
        break;
      default:
        i--;
        if (i + lens.len > end) {
          text = new byte[end - begin];
          for (int t = 0; t < end - begin; t++) {
            text[t] = data[i + t];
          }
          ansData.push_back({"", end - begin, text, type});
        } else {
          text = new byte[lens.len];
          for (int t = 0; t < lens.len; t++) {
            text[t] = data[i + t];
          }
          ansData.push_back({"", lens.len, text, type});
        }
        i = end;
    }
    i += lens.len;
  }
}

void printTime(string timeStr) {
  cout << "20" << timeStr[0] << timeStr[1] << "��";
  cout << timeStr[2] << timeStr[3] << "��";
  cout << timeStr[4] << timeStr[5] << "��";
  cout << timeStr[6] << timeStr[7] << ":";
  cout << timeStr[8] << timeStr[9] << ":";
  cout << timeStr[10] << timeStr[11];
}

void printHex(byte* data, int len) {
  cout << hex;
  for (int t = 0; t < len; t++) {
    cout << ((data[t] & 0xf0) >> 4) << (data[t] & 0xf);
  }
  cout << dec << endl;
}

void printHexLimit(byte* data, int len) {
  cout << hex;
  for (int t = 0; t < len; t++) {
    cout << ((data[t] & 0xf0) >> 4) << (data[t] & 0xf);
    if (t % 30 == 29) cout << endl;
  }
  cout << dec << endl;
}

void printRes() {
  std::map<string, string> titleToString = {
      {"1.3.6.1.5.5.7.3.1", "�����������֤(id_kp_serverAuth): True"},
      {"1.3.6.1.5.5.7.3.2", "�ͻ��������֤(id_kp_clientAuth): True"},
      {"2.5.29.37", "��չ��Կ�÷�(Extended key usage):"},
      {"Extension", "��չ�ֶΣ�"},
      {"1.3.6.1.5.5.7.3.2", "�ͻ��������֤(id_kp_clientAuth): True"}};
  std::map<string, string> titleToHex = {
      {"2.5.29.35", "��Ȩ��Կ��ʶ��(Authority Key Identifier): "},
      {"2.5.29.14", "������Կ��ʶ��(Subject Key Identifier): "}};
  std::map<string, string> titleToNext = {
      {"2.5.29.32", "֤�����(Certificate Policies): "},
      {"2.5.29.15", "ʹ����Կ(Key Usage): "},
      {"1.3.6.1.5.5.7.2.1", "OID for CPS qualifier: "},
      {"1.3.6.1.5.5.7.48.1", "OCSP: "},
      {"1.3.6.1.5.5.7.48.2", "id-ad-caIssuers: "},
      {"2.5.29.19", "����Լ��(Basic Constraints): "},
      {"2.5.4.6", "�䷢�ߣ�\n������(id-at-countryName): "},
      {"2.5.4.10", "��֯��(id-at-organizationName): "},
      {"2.5.4.11", "��֯��λ��(id-at-organizationalUnitName): "},
      {"2.5.4.3", "ͨ������(id-at-commonName): "}};

  for (int i = 0; i < ansData.size(); i++) {
    Item item = ansData[i];
    if (!strcmp(item.title.c_str(), "Version")) {
      item = ansData[++i];
      if (item.type == 0x02) {
        cout << "֤��汾: ";
        cout << "V" << item.data[0] + 1 << endl;
        item = ansData[++i];
        cout << "���к�: ";
        printHex(item.data, item.len);
      } else {
        i--;
      }
    } else if (titleToString.find(item.title) != titleToString.end()) {
      cout << titleToString[item.title] << endl;
    } else if (titleToHex.find(item.title) != titleToHex.end()) {
      string title = titleToHex[item.title];
      item = ansData[++i];
      if (item.data != NULL) {
        cout << title;
        printHex(item.data, item.len);
      } else {
        i--;
      }
    } else if (titleToNext.find(item.title) != titleToNext.end()) {
      cout << titleToNext[item.title];
      item = ansData[++i];
      cout << item.title << endl;
    } else if (!strcmp(item.title.c_str(), "1.2.840.113549.1.1.11")) {
      cout << "�����㷨: sha256WithRSAEncryption" << endl;
      item = ansData[++i];
      if (item.type == 0x03) {
        cout << "RSA��Կ��" << endl;
        printHexLimit(item.data, item.len);
      } else {
        i--;
      }
    } else if (!strcmp(item.title.c_str(), "1.2.840.113549.1.1.1")) {
      cout << "�����㷨: RSA encryption\nRSA��Կ��" << endl;
      item = ansData[++i];
      printHexLimit(item.data, item.len);
    } else if (!strcmp(item.title.c_str(), "0x00")) {
      cout << "��Կ: " << endl;
      printHexLimit(item.data, item.len);
    } else if (!strcmp(item.title.c_str(), "2.5.29.17")) {
      cout << "�������(Subject Alternative Name): ";
      item = ansData[++i];
      cout << item.title;
      item = ansData[++i];
      while (item.type == 0x82) {
        cout << ", " << item.title;
        item = ansData[++i];
      }
      i--;
      cout << endl;
    } else if (item.title.length() > 7 &&
               !strcmp(item.title.substr(0, 7).c_str(), "UTCTime")) {
      cout << "��Ч��: ";
      string beginTime = item.title.substr(7, item.title.length() - 8);
      printTime(beginTime);
      cout << " - ";
      item = ansData[++i];
      string endTime = item.title.substr(7, item.title.length() - 8);
      printTime(endTime);
      cout << endl;
    } else {
      cout << item.title << endl;
    }
  }
}

void printDebug() {
  for (int i = 0; i < ansData.size(); i++) {
    Item item = ansData[i];
    cout << item.title << endl;
    if (item.data != NULL) {
      printHex(item.data, item.len);
    }
  }
}

void parseX509(string data) {
  // Base64 ����
  while (data.length() % 4 != 0) {
    cout << "Error" << endl;
    data.append("=");
  }
  int len = (data.length() / 4) * 3;
  cout << "֤�鳤�ȣ�" << len << endl;
  byte text[len] = {0};
  int textIndex = 0;
  for (int i = 0; i < data.length(); i += 4) {
    byte base64_bit_6[4];
    for (int j = 0; j < 4; j++) {
      base64_bit_6[j] = base64_chars.find(data[i + j]);
    }
    text[textIndex] =
        ((base64_bit_6[0] & 0x3f) << 2) | ((base64_bit_6[1] & 0x30) >> 4);
    text[textIndex + 1] =
        ((base64_bit_6[1] & 0xf) << 4) | ((base64_bit_6[2] & 0x3c) >> 2);
    text[textIndex + 2] =
        ((base64_bit_6[2] & 0x3) << 6) | (base64_bit_6[3] & 0x3f);
    textIndex += 3;
  }

  // ANS.1 ����
  ansData.clear();
  parseANS(text, 0, len);
  // �������
  printRes();
  // printDebug();
}
