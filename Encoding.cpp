#include "Encoding.h"

std::string hexify(std::string naive) {
	std::string hexed = std::string();
	static const char* const lut = "0123456789ABCDEF";
	for (uint8_t c : naive) {
		if (c > 127) {
			char c1 = lut[c >> 4];
			char c2 = lut[c & 15];
			hexed.push_back(c1);
			hexed.push_back(c2);
		}
		else
			hexed.push_back(c);
	}
	return hexed;
}

std::string MBstr_to_UTFstr_WinAPI(std::string multibyte_str) {
	if (multibyte_str.empty())
		return multibyte_str;

	char* pszIn = new char[multibyte_str.length() + 1];
	strncpy_s(pszIn, multibyte_str.length() + 1, multibyte_str.c_str(), multibyte_str.length());

	std::string resultString;

	size_t nLenOfUni = 0, nLenOfUTF = 0;
	wchar_t* uni_wchar = NULL;
	char* pszOut = NULL;

	// 1. ANSI(multibyte) Length
	nLenOfUni = MultiByteToWideChar(949, 0, pszIn, (int)strlen(pszIn), NULL, 0);

	uni_wchar = new wchar_t[nLenOfUni + 1];
	memset(uni_wchar, 0x00, sizeof(wchar_t) * (nLenOfUni + 1));

	// 2. ANSI(multibyte) -> unicode
	nLenOfUni = MultiByteToWideChar(949, 0, pszIn, (int)strlen(pszIn), uni_wchar, nLenOfUni);

	// 3. utf8 Length
	nLenOfUTF = WideCharToMultiByte(CP_UTF8, 0, uni_wchar, nLenOfUni, NULL, 0, NULL, NULL);

	pszOut = new char[nLenOfUTF + 1];
	memset(pszOut, 0, sizeof(char) * (nLenOfUTF + 1));

	// 4. unicode -> utf8
	nLenOfUTF = WideCharToMultiByte(CP_UTF8, 0, uni_wchar, nLenOfUni, pszOut, nLenOfUTF, NULL, NULL);
	pszOut[nLenOfUTF] = 0;
	resultString = pszOut;

	delete[] uni_wchar;
	delete[] pszOut;

	return resultString;
}

std::string decode_filename(uint8_t*& ptr) {
	
	std::string naive = std::string(reinterpret_cast<char*>(ptr));
	ptr += naive.length() + 1;

	// just assume everything is ASCII
	//return naive;

	// output eveything outside ASCII range as hex
	//return hexify(naive);

	// convert CP949 string to UTF string
	return MBstr_to_UTFstr_WinAPI(naive);
}

