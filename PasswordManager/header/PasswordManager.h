#pragma once

#include "common.h"

struct Entry {
	std::string host, name;
	CryptoPP::SecByteBlock password;

	std::string to_string() {
		return std::string(host + '\n' + name + '\n' + (char*)password.BytePtr() + "\n");
	}
	void from_string(const std::string& str) {
		if (std::count(str.begin(), str.end(), '\n') != 3) throw std::runtime_error("Entry::form_string: bad input");
		std::string pw;

		std::istringstream is(str);
		std::getline(is, host);
		std::getline(is, name);
		std::getline(is, pw);

		password.New(pw.size());
		password.Assign((CryptoPP::byte*)pw.c_str(), pw.size());
	}

	static Entry static_from_string(const std::string& str) {
		Entry en;
		en.from_string(str);
		return en;
	}
};

class PasswordManager {
#ifndef _WIN32
#include <unistd.h>
#include <termios.h>

	char _getch() {
		char buf = 0;
		struct termios old = { 0 };
		fflush(stdout);
		if (tcgetattr(0, &old) < 0)
			perror("tcsetattr()");
		old.c_lflag &= ~ICANON;
		old.c_lflag &= ~ECHO;
		old.c_cc[VMIN] = 1;
		old.c_cc[VTIME] = 0;
		if (tcsetattr(0, TCSANOW, &old) < 0)
			perror("tcsetattr ICANON");
		if (read(0, &buf, 1) < 0)
			perror("read()");
		old.c_lflag |= ICANON;
		old.c_lflag |= ECHO;
		if (tcsetattr(0, TCSADRAIN, &old) < 0)
			perror("tcsetattr ~ICANON");
		return buf;
	}
#endif // !_WIN32

	static const std::string VERSION;
	static const int SALT_LEN = 16, MAX_PASSWORD_LEN = 32, FILE_INIT_SIZE = CryptoPP::Whirlpool::DIGESTSIZE + SALT_LEN * 3;
	bool quit;

	const std::map<std::string_view, std::function<void()>> comands_ = {
		{"list", [this]() {std::cout << "List of comands: \n"; for (auto str : comands_) std::cout << "- " << str.first << "\n"; }},
		{"exit", [this]() {quit = true; }},
		{"about", [this]() {std::cout << "PasswordManager " << VERSION << " by Marc Hofmann.\n"; }},
		{"save", [this]() {SaveDatabase(); }},
		{"entries", [this]() { for (auto& e : entries_) std::cout << e.host << ": " << e.name << "\n"; }},
		{"add", [this]() {AddEntry(); }},
		{"delete", [this]() {
			DeleteDatabase();
			exit(EXIT_SUCCESS);
		}},
		{"regen", [this]() {GenerateDatabase(); }},
		{"load", [this]() {LoadDatabase(); }}
	};
	//Cryptographie
	const int TAG_SIZE = 12;
	CryptoPP::Whirlpool hash_algo_;
	CryptoPP::GCM<CryptoPP::Serpent>::Encryption gcm_en_;
	CryptoPP::GCM<CryptoPP::Serpent>::Decryption gcm_de_;
	CryptoPP::byte digest_[CryptoPP::Whirlpool::DIGESTSIZE],
		hash_salt_[SALT_LEN],
		hkdf_salt_[2][SALT_LEN];
	CryptoPP::SecByteBlock key_, iv_;

	//einträge
	std::vector<Entry> entries_;

	//misc
	std::string database_file_;
	std::fstream file_handle_;

	//methoden
	//cryptographie
	void InitCrypt(CryptoPP::byte* pw, size_t size);

	//datenbank verwaltung
	void LoadDatabase();
	void SaveDatabase();
	void GenerateDatabase();
	void AddEntry();
	
	//input
	void ProcessInput(const std::string& str);
	
	//misc
	std::string InputPassword();
	void DeleteDatabase();
	void OnError();
public:
	PasswordManager(const std::string& database);
	~PasswordManager();
	PasswordManager(const PasswordManager& other) = delete;
	void operator = (const PasswordManager& other) = delete;

	void Run();
};

