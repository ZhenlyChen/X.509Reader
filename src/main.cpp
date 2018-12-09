#include <cstring>
#include <fstream>
#include <iostream>
#include "x509.h"
#define isLinux false

using namespace std;

int main(int argc, char const *argv[]) {
  string fileName;
  string base64Str = "";
  if (argc > 1) {
    fileName = string(argv[1]);
    ifstream in(fileName);
    if (!in.is_open()) {
      cout << "Error opening file";
      exit(1);
    }
    cout << fileName << endl;
    char buffer[1024];
    while (!in.eof()) {
      in.getline(buffer, 1024);
      if (string(buffer).find("BEGIN CERTIFICATE") != -1) {
        cout << "Begin" << endl;
      } else if (string(buffer).find("END CERTIFICATE") != -1) {
        parseX509(base64Str);
        cout << "End" << endl << endl;
        base64Str = "";
      } else {
#if isLinux
        string data = string(buffer);
        base64Str += data.substr(0, data.length() - 1);
#else
        base64Str.append(buffer);
#endif
      }
    }
  } else {
    string data;
    while (!cin.eof()) {
      getline(cin, data);
      // cout << data << endl;
      if (data.find("BEGIN CERTIFICATE") != -1) {
        cout << "Begin" << endl;
      } else if (data.find("END CERTIFICATE") != -1) {
        parseX509(base64Str);
        cout << "End" << endl << endl;
        data = "";
      } else {
#if isLinux
        base64Str += data.substr(0, data.length() - 1);
#else
        base64Str += data;
#endif
      }
    }
  }
  return 0;
}
