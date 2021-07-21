#pragma once

#include "common.h"

struct Entry {
	std::string hostname, username;
	CryptoPP::SecByteBlock password;

	std::string to_string() {
		return std::string(hostname + '\n' + username + '\n' + (char*)password.BytePtr() + "\n");
	}
	void from_string(const std::string& str) {
		if (std::count(str.begin(), str.end(), '\n') != 3) throw std::runtime_error("Entry::form_string: bad input");
		std::string pw;

		std::istringstream is(str);
		std::getline(is, hostname);
		std::getline(is, username);
		std::getline(is, pw);

		password.New(pw.size());
		password.Assign((CryptoPP::byte*)pw.c_str(), pw.size());
	}
};

class Database {
	static const std::string VERSION;
	static const int SALT_LEN = 16,
		MAX_PASSWORD_LEN = 32,
		FILE_INIT_SIZE = CryptoPP::Whirlpool::DIGESTSIZE + SALT_LEN * 3;
	bool quit_, verified_, init_;

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
	std::function<void(const std::string&)> error_callback_;

	//methoden
	//cryptographie
	void GenerateKeys(CryptoPP::byte* pw, size_t size);
	
	//misc
	void OnError(const std::string& msg);
public:
	Database();
	~Database();
	Database(const Database& other) = delete;
	void operator = (const Database& other) = delete;

	//datenbank verwaltung
	bool VerifyPassword(const std::string& password);
	void LoadDatabase();
	void SaveDatabase();
	void GenerateDatabase(const std::string& password);
	void InitDatabase();
	void DeleteDatabase();
	void AddEntry(const std::string& hostname, const std::string& username, const std::string& password);

	inline void set_error_callback(std::function<void(const std::string&)> error_callback) {
		error_callback_ = error_callback;
	}
	inline void set_database_file(const std::string& file) {
		database_file_ = file;
	}
};

