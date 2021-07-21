#include "../header/Database.h"

const std::string Database::VERSION = "v. 0.0.0";

//private 
void Database::GenerateKeys(CryptoPP::byte* pw, size_t size) {
	CryptoPP::HKDF<decltype(hash_algo_)> hkdf;

	hkdf.DeriveKey(key_.BytePtr(), key_.size(), pw, size, hkdf_salt_[0], sizeof(hkdf_salt_[0]), nullptr, 0);
	hkdf.DeriveKey(iv_.BytePtr(), iv_.SizeInBytes(), pw, size, hkdf_salt_[1], sizeof(hkdf_salt_[1]), nullptr, 0);
}

bool Database::VerifyPassword(const std::string& password) {
	if (!init_) OnError("Can't verify Password before initialisation.");
	if (hash_algo_.VerifyDigest(digest_, (CryptoPP::byte*)password.c_str(), password.length())) {
		verified_ = true;
		return true;
	}
	return false;
}

void Database::LoadDatabase() {
	if (!verified_) OnError("Can't load database before verifing password.");

	std::string file_dec;
	
	file_handle_.open(database_file_, std::ios::in | std::ios::binary);
	if (!file_handle_.good()) OnError("Can't open database.");
	file_handle_.seekg(FILE_INIT_SIZE);

	gcm_de_.SetKeyWithIV(key_.BytePtr(), key_.SizeInBytes(), iv_);
	CryptoPP::AuthenticatedDecryptionFilter adf(gcm_de_, new CryptoPP::StringSink(file_dec), CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS, TAG_SIZE);
	CryptoPP::FileSource ss(file_handle_, true, new CryptoPP::Redirector(adf));
	
	file_handle_.close();

	if (!adf.GetLastResult() || std::count(file_dec.begin(), file_dec.end(), '\n') % 3 != 0) {
		OnError("Couldn't decrypt database.");
	}

	bool r = true;
	std::istringstream iss(file_dec);
	while (r) {
		Entry n;
		std::string pw;
		std::getline(iss, n.hostname);
		std::getline(iss, n.username);
		std::getline(iss, pw);

		if (iss.eof()) {
			r = false;
			continue;
		}

		n.password.New(pw.length());
		n.password.Assign((CryptoPP::byte*)pw.c_str(), pw.length());
		entries_.push_back(n);
	}
}
void Database::SaveDatabase() {
	file_handle_.open(database_file_, std::ios::out | std::ios::trunc | std::ios::binary);
	if (!file_handle_.good()) OnError("Can't open database.");

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
void Database::GenerateDatabase(const std::string& password) {
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

	GenerateKeys((CryptoPP::byte*)password.c_str(), password.length());

	SaveDatabase();
	init_ = true;
}
void Database::AddEntry(const std::string& hostname, const std::string& username, const std::string& password) {
	Entry entry;
	entry.hostname = hostname;
	entry.username = username;
	entry.password.New(password.size());
	entry.password.Assign((CryptoPP::byte*)password.c_str(), password.size());
	entries_.push_back(entry);
}

void Database::DeleteDatabase() {
	std::filesystem::remove(database_file_);
	std::filesystem::remove("init" + database_file_);
}

void Database::OnError(const std::string& msg) {
	if (error_callback_) {
		error_callback_(msg);
	}
	else {
		std::cerr << "Fatal error occured. Please try again.\n";
		if (file_handle_.is_open()) file_handle_.close();
	}
	abort();
}

//public
Database::Database() 
	: quit_{ false },
		verified_{ false },
		init_{ false } {
	key_.New(gcm_de_.DefaultKeyLength());
	iv_.New(gcm_de_.DefaultIVLength());
}
Database::~Database() {}

void Database::InitDatabase() {
	if (std::filesystem::is_regular_file(database_file_)) {
		file_handle_.open(database_file_, std::ios::in | std::ios::binary);
		if (!file_handle_.is_open()) {
			OnError("Cannot open database file.");
		}

		file_handle_.read((char*)digest_, sizeof(digest_));
		if (!file_handle_.good()) {
			OnError("Failed to fetch data from file.");
		}
		file_handle_.read((char*)hash_salt_, sizeof(hash_salt_));
		if (!file_handle_.good()) {
			OnError("Failed to fetch data from file.");
		}
		file_handle_.read((char*)hkdf_salt_[0], sizeof(hkdf_salt_[0]));
		if (!file_handle_.good()) {
			OnError("Failed to fetch data from file.");
		}
		file_handle_.read((char*)hkdf_salt_[1], sizeof(hkdf_salt_[1]));
		if (!file_handle_.good()) {
			OnError("Failed to fetch data from file.");
		}
		file_handle_.close();
		init_ = true;
	}
}