#include "PasswordManager.h"

const std::string PasswordManager::VERSION = "v. 0.0.0";

//private 
void PasswordManager::InitCrypt(CryptoPP::byte* pw, size_t size) {
	CryptoPP::HKDF<decltype(hash_algo_)> hkdf;

	hkdf.DeriveKey(key_.BytePtr(), key_.size(), pw, size, hkdf_salt_[0], sizeof(hkdf_salt_[0]), nullptr, 0);
	hkdf.DeriveKey(iv_.BytePtr(), iv_.SizeInBytes(), pw, size, hkdf_salt_[1], sizeof(hkdf_salt_[1]), nullptr, 0);
}

void PasswordManager::LoadDatabase() {
	std::cout << "--- load Database ---\n";

	file_handle_.open(database_file_, std::ios::in | std::ios::binary);
	if (!file_handle_.is_open()) {
		std::cout << "Cannot open database file.\n";
		DeleteDatabase();
		exit(EXIT_FAILURE);
	}

	file_handle_.read((char*)digest_, sizeof(digest_));
	if (!file_handle_.good()) {
		std::cout << "Failed to fetch data from file.\n";
		OnError();
	}
	file_handle_.read((char*)hash_salt_, sizeof(hash_salt_));
	if (!file_handle_.good()) {
		std::cout << "Failed to fetch data from file.\n";
		OnError();
	}
	file_handle_.read((char*)hkdf_salt_[0], sizeof(hkdf_salt_[0]));
	if (!file_handle_.good()) {
		std::cout << "Fauled to fetch data from file.\n";
		OnError();
	}
	file_handle_.read((char*)hkdf_salt_[1], sizeof(hkdf_salt_[1]));
	if (!file_handle_.good()) {
		std::cout << "Failed to fetch data from file1.\n";
		OnError();
	}

	std::string pw;
	do {
		std::cout << "Please enter your password: ";
		pw = InputPassword();
		pw.append((char*)hash_salt_, sizeof(hash_salt_));
	} while (!hash_algo_.VerifyDigest(digest_, (CryptoPP::byte*)pw.c_str(), pw.length()));

	InitCrypt((CryptoPP::byte*)pw.c_str(), pw.length());

	std::string file_dec;


	gcm_de_.SetKeyWithIV(key_.BytePtr(), key_.SizeInBytes(), iv_);
	CryptoPP::AuthenticatedDecryptionFilter adf(gcm_de_, new CryptoPP::StringSink(file_dec), CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS, TAG_SIZE);
	CryptoPP::FileSource ss(file_handle_, true, new CryptoPP::Redirector(adf));
	file_handle_.close();

	if (!adf.GetLastResult() || std::count(file_dec.begin(), file_dec.end(), '\n') % 3 != 0) {
		throw std::runtime_error("Couldn't decrypt file / fatal error");
	}

	std::istringstream iss(file_dec);
	while (!iss.eof()) {
		Entry n;
		std::string pw;
		std::getline(iss, n.host);
		std::getline(iss, n.name);
		std::getline(iss, pw);
		n.password.New(pw.length());
		n.password.Assign((CryptoPP::byte*)pw.c_str(), pw.length());

		if (n.password.SizeInBytes() && n.host.length() && n.name.length())
			entries_.push_back(n);
	}
}
void PasswordManager::SaveDatabase() {
	std::cout << "--- saving Database ---\n";

	file_handle_.open(database_file_, std::ios::out | std::ios::trunc | std::ios::binary);
	file_handle_.write((const char*)digest_, sizeof(digest_));
	file_handle_.write((const char*)hash_salt_, sizeof(hash_salt_));
	file_handle_.write((const char*)hkdf_salt_[0], sizeof(hkdf_salt_[0]));
	file_handle_.write((const char*)hkdf_salt_[1], sizeof(hkdf_salt_[1]));

	std::string file;
	for (auto& e : entries_) {
		file.append(e.to_string());
	}

	gcm_en_.SetKeyWithIV(key_.BytePtr(), key_.SizeInBytes(), iv_);
	CryptoPP::StringSource ss(file, true,
		new CryptoPP::AuthenticatedEncryptionFilter(gcm_en_,
			new CryptoPP::FileSink(file_handle_), false, TAG_SIZE
		)
	);
	file_handle_.close();
}
void PasswordManager::GenerateDatabase() {
	std::cout << "--- create Database ---\n";

	typedef CryptoPP::Hash_DRBG<CryptoPP::SHA256, 128 / 8, 440 / 8> drbg_t;
	CryptoPP::NonblockingRng prng;
	CryptoPP::SecByteBlock entropy(drbg_t::MINIMUM_ENTROPY + drbg_t::MINIMUM_NONCE);

	prng.GenerateBlock(entropy.BytePtr(), entropy.size());

	drbg_t drbg(entropy, drbg_t::MINIMUM_ENTROPY, entropy + drbg_t::MINIMUM_ENTROPY, drbg_t::MINIMUM_NONCE);

	drbg.GenerateBlock(hash_salt_, sizeof(hash_salt_));

	prng.GenerateBlock(entropy.BytePtr(), drbg_t::MINIMUM_ENTROPY);
	drbg.IncorporateEntropy(entropy, drbg_t::MINIMUM_ENTROPY);

	drbg.GenerateBlock(hkdf_salt_[0], sizeof(hkdf_salt_[0]));

	prng.GenerateBlock(entropy.BytePtr(), drbg_t::MINIMUM_ENTROPY);
	drbg.IncorporateEntropy(entropy, drbg_t::MINIMUM_ENTROPY);

	drbg.GenerateBlock(hkdf_salt_[1], sizeof(hkdf_salt_[1]));

	std::cout << "Please enter a password: ";
	std::string pw = InputPassword();
	pw.append((char*)hash_salt_, sizeof(hash_salt_));
	CryptoPP::StringSource ss(pw, true, 
		new CryptoPP::HashFilter(hash_algo_, 
			new CryptoPP::ArraySink(digest_, sizeof(digest_))
		)
	);

	InitCrypt((CryptoPP::byte*)pw.c_str(), pw.length());

	SaveDatabase();
}
void PasswordManager::AddEntry() {
	std::string host, account_name, password;

	std::cout << "Host: ";
	std::getline(std::cin, host);

	std::cout << "User: ";
	std::getline(std::cin, account_name);

	std::cout << "Password: ";
	password = InputPassword();

	Entry entry;
	entry.host = host;
	entry.name = account_name;
	entry.password.New(password.size());
	entry.password.Assign((CryptoPP::byte*)password.c_str(), password.size());
	entries_.push_back(entry);
}

void PasswordManager::ProcessInput(const std::string& str) {
	std::string befehl;
	std::istringstream iss(str);
	iss >> befehl;
	
	auto res = comands_.find(str);
	if (res != comands_.end()) {
		res->second();
	}
	else {
		std::cout << "\"" << befehl << "\" is not an comand (try \"list\")\n";
	}
}

std::string PasswordManager::InputPassword() {
	char input = 0;
	std::string t;

	do {
		input = (char)_getch();
		if (input >= '!' && input <= '~' && t.length() < MAX_PASSWORD_LEN) {
			t += input;
			std::cout << "*";
		}
		else if (input == '\b' && t.length() > 0) {
			std::cout << "\b \b";
			t.pop_back();
		}
	} while (input != '\n' && input != '\r');
	std::cout << "\n";
	return t;
}

void PasswordManager::DeleteDatabase() {
	std::filesystem::remove(database_file_);
	std::filesystem::remove("init" + database_file_);
}

void PasswordManager::OnError() {
	std::cerr << "Fatal error occured. Please try again.\n";
	if (file_handle_.is_open()) file_handle_.close();
	DeleteDatabase();
	abort();
}

//public
PasswordManager::PasswordManager(const std::string& database) 
	: quit{ false } {
	database_file_ = database;
	key_.New(gcm_de_.DefaultKeyLength());
	iv_.New(gcm_de_.DefaultIVLength());
	try {
		if (std::filesystem::is_regular_file(database)) {
			LoadDatabase();
		}
		else {
			GenerateDatabase();
		}
	}
	catch (std::exception& ex) {
		std::cerr << ex.what() << std::endl;
		OnError();
	}
	catch (...) {
		OnError();
	}
}
PasswordManager::~PasswordManager() {}

void PasswordManager::Run() {
	std::string input;
	while (!quit) {
		std::cout << "\nPwMng << ";
		std::getline(std::cin, input);
		if (!std::cin.good()) {
			std::cin.clear();
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
		}
		std::transform(input.begin(), input.end(), input.begin(),
			[](char c) {
				return std::tolower(c);
			});
		input.erase(std::remove(input.begin(), input.end(), ' '), input.end());
		std::cout << "\n";
		try {
			ProcessInput(input);
		}
		catch (std::exception& ex) {
			std::cerr << ex.what() << std::endl;
			OnError();
		}
		catch (...) {
			OnError();		
		}
	}
}