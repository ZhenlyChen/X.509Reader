#include <cstring>
#include <fstream>
#include <iostream>
#include "x509.h"

using namespace std;

int main(int argc, char const *argv[]) {
  string fileName;
  if (argc > 1) {
    fileName = string(argv[1]);
  }
  ifstream in(fileName);
  if (!in.is_open()) {
    cout << "Error opening file";
    exit(1);
  }
  cout << fileName << endl;
  string fileData;
  char buffer[1024];
  bool isContent = false;
  while (!in.eof()) {
    in.getline(buffer, 1024);
    if (!strcmp(buffer, "-----BEGIN CERTIFICATE-----")) {
      isContent = true;
      cout << "Begin" << endl;
    } else if (!strcmp(buffer, "-----END CERTIFICATE-----")) {
      parseX509(fileData);
      isContent = false;
      cout << "End" << endl << endl;
      fileData = "";
    } else {
      fileData.append(buffer);
    }
  }
  return 0;
}
