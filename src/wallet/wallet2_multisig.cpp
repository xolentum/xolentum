// Copyright (c) 2014-2020, The Monero Project
// Copyright (c) 2020, The Xolentum Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "include_base_utils.h"
#include "cryptonote_config.h"
#include "wallet2.h"
#include "ringct/rctSigs.h"
#include "multisig/multisig.h"

#include <boost/format.hpp>
#include <boost/optional/optional.hpp>

#include "mnemonics/electrum-words.h"

#include "common/base58.h"
#include "common/combinator.h"

extern "C"
{
#include "crypto/keccak.h"
#include "crypto/crypto-ops.h"
}
using namespace std;
using namespace crypto;
using namespace cryptonote;

#define MULTISIG_EXPORT_FILE_MAGIC "Xolentum multisig export\001"

#define MULTISIG_UNSIGNED_TX_PREFIX "Xolentum multisig unsigned tx set\001"

static const std::string MULTISIG_SIGNATURE_MAGIC = "SigMultisigPkV1";
static const std::string MULTISIG_EXTRA_INFO_MAGIC = "MultisigxV1";

namespace{
  std::vector<crypto::public_key> secret_keys_to_public_keys(const std::vector<crypto::secret_key>& keys)
  {
    std::vector<crypto::public_key> public_keys;
    public_keys.reserve(keys.size());

    std::transform(keys.begin(), keys.end(), std::back_inserter(public_keys), [] (const crypto::secret_key& k) -> crypto::public_key {
      crypto::public_key p;
      CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(k, p), "Failed to derive public spend key");
      return p;
    });

    return public_keys;
  }
  bool keys_intersect(const std::unordered_set<crypto::public_key>& s1, const std::unordered_set<crypto::public_key>& s2)
  {
    if (s1.empty() || s2.empty())
      return false;

    for (const auto& e: s1)
    {
      if (s2.find(e) != s2.end())
        return true;
    }

    return false;
  }
  std::string pack_multisignature_keys(const std::string& prefix, const std::vector<crypto::public_key>& keys, const crypto::secret_key& signer_secret_key)
  {
    std::string data;
    crypto::public_key signer;
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(signer_secret_key, signer), "Failed to derive public spend key");
    data += std::string((const char *)&signer, sizeof(crypto::public_key));

    for (const auto &key: keys)
    {
      data += std::string((const char *)&key, sizeof(crypto::public_key));
    }

    data.resize(data.size() + sizeof(crypto::signature));

    crypto::hash hash;
    crypto::cn_fast_hash(data.data(), data.size() - sizeof(crypto::signature), hash);
    crypto::signature &signature = *(crypto::signature*)&data[data.size() - sizeof(crypto::signature)];
    crypto::generate_signature(hash, signer, signer_secret_key, signature);

    return MULTISIG_EXTRA_INFO_MAGIC + tools::base58::encode(data);
  }
}

//this namespace contain shared functions from wallet2
namespace _wallet2_internal{
  tools::wallet2::tx_construction_data get_construction_data_with_decrypted_short_payment_id(const tools::wallet2::pending_tx &ptx, hw::device &hwdev);
}

using namespace _wallet2_internal;

namespace tools{
  //----------------------------------------------------------------------------------------------------
  bool wallet2::get_multisig_seed(epee::wipeable_string& seed, const epee::wipeable_string &passphrase, bool raw) const
  {
    bool ready;
    uint32_t threshold, total;
    if (!multisig(&ready, &threshold, &total))
    {
      std::cout << "This is not a multisig wallet" << std::endl;
      return false;
    }
    if (!ready)
    {
      std::cout << "This multisig wallet is not yet finalized" << std::endl;
      return false;
    }
    if (!raw && seed_language.empty())
    {
      std::cout << "seed_language not set" << std::endl;
      return false;
    }

    crypto::secret_key skey;
    crypto::public_key pkey;
    const account_keys &keys = get_account().get_keys();
    epee::wipeable_string data;
    data.append((const char*)&threshold, sizeof(uint32_t));
    data.append((const char*)&total, sizeof(uint32_t));
    skey = keys.m_spend_secret_key;
    data.append((const char*)&skey, sizeof(skey));
    pkey = keys.m_account_address.m_spend_public_key;
    data.append((const char*)&pkey, sizeof(pkey));
    skey = keys.m_view_secret_key;
    data.append((const char*)&skey, sizeof(skey));
    pkey = keys.m_account_address.m_view_public_key;
    data.append((const char*)&pkey, sizeof(pkey));
    for (const auto &skey: keys.m_multisig_keys)
      data.append((const char*)&skey, sizeof(skey));
    for (const auto &signer: m_multisig_signers)
      data.append((const char*)&signer, sizeof(signer));

    if (!passphrase.empty())
    {
      crypto::secret_key key;
      crypto::cn_slow_hash(passphrase.data(), passphrase.size(), (crypto::hash&)key);
      sc_reduce32((unsigned char*)key.data);
      data = encrypt(data, key, true);
    }

    if (raw)
    {
      seed = epee::to_hex::wipeable_string({(const unsigned char*)data.data(), data.size()});
    }
    else
    {
      if (!crypto::ElectrumWords::bytes_to_words(data.data(), data.size(), seed, seed_language))
      {
        std::cout << "Failed to encode seed";
        return false;
      }
    }

    return true;
  }
  std::string wallet2::make_multisig(const epee::wipeable_string &password,
    const std::vector<crypto::secret_key> &view_keys,
    const std::vector<crypto::public_key> &spend_keys,
    uint32_t threshold)
  {
    CHECK_AND_ASSERT_THROW_MES(!view_keys.empty(), "empty view keys");
    CHECK_AND_ASSERT_THROW_MES(view_keys.size() == spend_keys.size(), "Mismatched view/spend key sizes");
    CHECK_AND_ASSERT_THROW_MES(threshold > 1 && threshold <= spend_keys.size() + 1, "Invalid threshold");

    std::string extra_multisig_info;
    std::vector<crypto::secret_key> multisig_keys;
    rct::key spend_pkey = rct::identity();
    rct::key spend_skey;
    auto wiper = epee::misc_utils::create_scope_leave_handler([&](){memwipe(&spend_skey, sizeof(spend_skey));});
    std::vector<crypto::public_key> multisig_signers;

    // decrypt keys
    epee::misc_utils::auto_scope_leave_caller keys_reencryptor;
    if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
    {
      crypto::chacha_key chacha_key;
      crypto::generate_chacha_key(password.data(), password.size(), chacha_key, m_kdf_rounds);
      m_account.encrypt_viewkey(chacha_key);
      m_account.decrypt_keys(chacha_key);
      keys_reencryptor = epee::misc_utils::create_scope_leave_handler([&, this, chacha_key]() { m_account.encrypt_keys(chacha_key); m_account.decrypt_viewkey(chacha_key); });
    }

    // In common multisig scheme there are 4 types of key exchange rounds:
    // 1. First round is exchange of view secret keys and public spend keys.
    // 2. Middle round is exchange of derivations: Ki = b * Mj, where b - spend secret key,
    //    M - public multisig key (in first round it equals to public spend key), K - new public multisig key.
    // 3. Secret spend establishment round sets your secret multisig keys as follows: kl = H(Ml), where M - is *your* public multisig key,
    //    k - secret multisig key used to sign transactions. k and M are sets of keys, of course.
    //    And secret spend key as the sum of all participant's secret multisig keys
    // 4. Last round establishes multisig wallet's public spend key. Participants exchange their public multisig keys
    //    and calculate common spend public key as sum of all unique participants' public multisig keys.
    // Note that N/N scheme has only first round. N-1/N has 2 rounds: first and last. Common M/N has all 4 rounds.

    // IMPORTANT: wallet's public spend key is not equal to secret_spend_key * G!
    // Wallet's public spend key is the sum of unique public multisig keys of all participants.
    // secret_spend_key * G = public signer key

    if (threshold == spend_keys.size() + 1)
    {
      // In N / N case we only need to do one round and calculate secret multisig keys and new secret spend key
      MINFO("Creating spend key...");

      // Calculates all multisig keys and spend key
      cryptonote::generate_multisig_N_N(get_account().get_keys(), spend_keys, multisig_keys, spend_skey, spend_pkey);

      // Our signer key is b * G, where b is secret spend key.
      multisig_signers = spend_keys;
      multisig_signers.push_back(get_multisig_signer_public_key(get_account().get_keys().m_spend_secret_key));
    }
    else
    {
      // We just got public spend keys of all participants and deriving multisig keys (set of Mi = b * Bi).
      // note that derivations are public keys as DH exchange suppose it to be
      auto derivations = cryptonote::generate_multisig_derivations(get_account().get_keys(), spend_keys);

      spend_pkey = rct::identity();
      multisig_signers = std::vector<crypto::public_key>(spend_keys.size() + 1, crypto::null_pkey);

      if (threshold == spend_keys.size())
      {
        // N - 1 / N case

        // We need an extra step, so we package all the composite public keys
        // we know about, and make a signed string out of them
        MINFO("Creating spend key...");

        // Calculating set of our secret multisig keys as follows: mi = H(Mi),
        // where mi - secret multisig key, Mi - others' participants public multisig key
        multisig_keys = cryptonote::calculate_multisig_keys(derivations);

        // calculating current participant's spend secret key as sum of all secret multisig keys for current participant.
        // IMPORTANT: participant's secret spend key is not an entire wallet's secret spend!
        //            Entire wallet's secret spend is sum of all unique secret multisig keys
        //            among all of participants and is not held by anyone!
        spend_skey = rct::sk2rct(cryptonote::calculate_multisig_signer_key(multisig_keys));

        // Preparing data for the last round to calculate common public spend key. The data contains public multisig keys.
        extra_multisig_info = pack_multisignature_keys(MULTISIG_EXTRA_INFO_MAGIC, secret_keys_to_public_keys(multisig_keys), rct::rct2sk(spend_skey));
      }
      else
      {
        // M / N case
        MINFO("Preparing keys for next exchange round...");

        // Preparing data for middle round - packing new public multisig keys to exchage with others.
        extra_multisig_info = pack_multisignature_keys(MULTISIG_EXTRA_INFO_MAGIC, derivations, m_account.get_keys().m_spend_secret_key);
        spend_skey = rct::sk2rct(m_account.get_keys().m_spend_secret_key);

        // Need to store middle keys to be able to proceed in case of wallet shutdown.
        m_multisig_derivations = derivations;
      }
    }

    if (!m_original_keys_available)
    {
      // Save the original i.e. non-multisig keys so the MMS can continue to use them to encrypt and decrypt messages
      // (making a wallet multisig overwrites those keys, see account_base::make_multisig)
      m_original_address = m_account.get_keys().m_account_address;
      m_original_view_secret_key = m_account.get_keys().m_view_secret_key;
      m_original_keys_available = true;
    }

    clear();
    MINFO("Creating view key...");
    crypto::secret_key view_skey = cryptonote::generate_multisig_view_secret_key(get_account().get_keys().m_view_secret_key, view_keys);

    MINFO("Creating multisig address...");
    CHECK_AND_ASSERT_THROW_MES(m_account.make_multisig(view_skey, rct::rct2sk(spend_skey), rct::rct2pk(spend_pkey), multisig_keys),
        "Failed to create multisig wallet due to bad keys");
    memwipe(&spend_skey, sizeof(rct::key));

    init_type(hw::device::device_type::SOFTWARE);
    m_original_keys_available = true;
    m_multisig = true;
    m_multisig_threshold = threshold;
    m_multisig_signers = multisig_signers;
    ++m_multisig_rounds_passed;

    // re-encrypt keys
    keys_reencryptor = epee::misc_utils::auto_scope_leave_caller();

    if (!m_wallet_file.empty())
      create_keys_file(m_wallet_file, false, password, boost::filesystem::exists(m_wallet_file + ".address.txt"));

    setup_new_blockchain();

    if (!m_wallet_file.empty())
      store();

    return extra_multisig_info;
  }

  std::string wallet2::exchange_multisig_keys(const epee::wipeable_string &password,
    const std::vector<std::string> &info)
  {
    THROW_WALLET_EXCEPTION_IF(info.empty(),
      error::wallet_internal_error, "Empty multisig info");

    if (info[0].substr(0, MULTISIG_EXTRA_INFO_MAGIC.size()) != MULTISIG_EXTRA_INFO_MAGIC)
    {
      THROW_WALLET_EXCEPTION_IF(false,
        error::wallet_internal_error, "Unsupported info string");
    }

    std::vector<crypto::public_key> signers;
    std::unordered_set<crypto::public_key> pkeys;

    THROW_WALLET_EXCEPTION_IF(!unpack_extra_multisig_info(info, signers, pkeys),
      error::wallet_internal_error, "Bad extra multisig info");

    return exchange_multisig_keys(password, pkeys, signers);
  }

  std::string wallet2::exchange_multisig_keys(const epee::wipeable_string &password,
    std::unordered_set<crypto::public_key> derivations,
    std::vector<crypto::public_key> signers)
  {
    CHECK_AND_ASSERT_THROW_MES(!derivations.empty(), "empty pkeys");
    CHECK_AND_ASSERT_THROW_MES(!signers.empty(), "empty signers");

    bool ready = false;
    CHECK_AND_ASSERT_THROW_MES(multisig(&ready), "The wallet is not multisig");
    CHECK_AND_ASSERT_THROW_MES(!ready, "Multisig wallet creation process has already been finished");

    // keys are decrypted
    epee::misc_utils::auto_scope_leave_caller keys_reencryptor;
    if (m_ask_password == AskPasswordToDecrypt && !m_unattended && !m_watch_only)
    {
      crypto::chacha_key chacha_key;
      crypto::generate_chacha_key(password.data(), password.size(), chacha_key, m_kdf_rounds);
      m_account.encrypt_viewkey(chacha_key);
      m_account.decrypt_keys(chacha_key);
      keys_reencryptor = epee::misc_utils::create_scope_leave_handler([&, this, chacha_key]() { m_account.encrypt_keys(chacha_key); m_account.decrypt_viewkey(chacha_key); });
    }

    if (m_multisig_rounds_passed == multisig_rounds_required(m_multisig_signers.size(), m_multisig_threshold) - 1)
    {
      // the last round is passed and we have to calculate spend public key
      // add ours if not included
      crypto::public_key local_signer = get_multisig_signer_public_key();

      if (std::find(signers.begin(), signers.end(), local_signer) == signers.end())
      {
          signers.push_back(local_signer);
          for (const auto &msk: get_account().get_multisig_keys())
          {
              derivations.insert(rct::rct2pk(rct::scalarmultBase(rct::sk2rct(msk))));
          }
      }

      CHECK_AND_ASSERT_THROW_MES(signers.size() == m_multisig_signers.size(), "Bad signers size");

      // Summing all of unique public multisig keys to calculate common public spend key
      crypto::public_key spend_public_key = cryptonote::generate_multisig_M_N_spend_public_key(std::vector<crypto::public_key>(derivations.begin(), derivations.end()));
      m_account_public_address.m_spend_public_key = spend_public_key;
      m_account.finalize_multisig(spend_public_key);

      m_multisig_signers = signers;
      std::sort(m_multisig_signers.begin(), m_multisig_signers.end(), [](const crypto::public_key &e0, const crypto::public_key &e1){ return memcmp(&e0, &e1, sizeof(e0)) < 0; });

      ++m_multisig_rounds_passed;
      m_multisig_derivations.clear();

      // keys are encrypted again
      keys_reencryptor = epee::misc_utils::auto_scope_leave_caller();

      if (!m_wallet_file.empty())
      {
        bool r = store_keys(m_keys_file, password, false);
        THROW_WALLET_EXCEPTION_IF(!r, error::file_save_error, m_keys_file);

        if (boost::filesystem::exists(m_wallet_file + ".address.txt"))
        {
          r = save_to_file(m_wallet_file + ".address.txt", m_account.get_public_address_str(m_nettype), true);
          if(!r) MERROR("String with address text not saved");
        }
      }

      m_subaddresses.clear();
      m_subaddress_labels.clear();
      add_subaddress_account(tr("Primary account"));

      if (!m_wallet_file.empty())
        store();

      return {};
    }

    // Below are either middle or secret spend key establishment rounds

    for (const auto& key: m_multisig_derivations)
      derivations.erase(key);

    // Deriving multisig keys (set of Mi = b * Bi) according to DH from other participants' multisig keys.
    auto new_derivations = cryptonote::generate_multisig_derivations(get_account().get_keys(), std::vector<crypto::public_key>(derivations.begin(), derivations.end()));

    std::string extra_multisig_info;
    if (m_multisig_rounds_passed == multisig_rounds_required(m_multisig_signers.size(), m_multisig_threshold) - 2) // next round is last
    {
      // Next round is last therefore we are performing secret spend establishment round as described above.
      MINFO("Creating spend key...");

      // Calculating our secret multisig keys by hashing our public multisig keys.
      auto multisig_keys = cryptonote::calculate_multisig_keys(std::vector<crypto::public_key>(new_derivations.begin(), new_derivations.end()));
      // And summing it to get personal secret spend key
      crypto::secret_key spend_skey = cryptonote::calculate_multisig_signer_key(multisig_keys);

      m_account.make_multisig(m_account.get_keys().m_view_secret_key, spend_skey, rct::rct2pk(rct::identity()), multisig_keys);

      // Packing public multisig keys to exchange with others and calculate common public spend key in the last round
      extra_multisig_info = pack_multisignature_keys(MULTISIG_EXTRA_INFO_MAGIC, secret_keys_to_public_keys(multisig_keys), spend_skey);
    }
    else
    {
      // This is just middle round
      MINFO("Preparing keys for next exchange round...");
      extra_multisig_info = pack_multisignature_keys(MULTISIG_EXTRA_INFO_MAGIC, new_derivations, m_account.get_keys().m_spend_secret_key);
      m_multisig_derivations = new_derivations;
    }

    ++m_multisig_rounds_passed;

    if (!m_wallet_file.empty())
      create_keys_file(m_wallet_file, false, password, boost::filesystem::exists(m_wallet_file + ".address.txt"));
    return extra_multisig_info;
  }

  void wallet2::unpack_multisig_info(const std::vector<std::string>& info,
    std::vector<crypto::public_key> &public_keys,
    std::vector<crypto::secret_key> &secret_keys) const
  {
    // parse all multisig info
    public_keys.resize(info.size());
    secret_keys.resize(info.size());
    for (size_t i = 0; i < info.size(); ++i)
    {
      THROW_WALLET_EXCEPTION_IF(!verify_multisig_info(info[i], secret_keys[i], public_keys[i]),
          error::wallet_internal_error, "Bad multisig info: " + info[i]);
    }

    // remove duplicates
    for (size_t i = 0; i < secret_keys.size(); ++i)
    {
      for (size_t j = i + 1; j < secret_keys.size(); ++j)
      {
        if (rct::sk2rct(secret_keys[i]) == rct::sk2rct(secret_keys[j]))
        {
          MDEBUG("Duplicate key found, ignoring");
          secret_keys[j] = secret_keys.back();
          public_keys[j] = public_keys.back();
          secret_keys.pop_back();
          public_keys.pop_back();
          --j;
        }
      }
    }

    // people may include their own, weed it out
    const crypto::secret_key local_skey = cryptonote::get_multisig_blinded_secret_key(get_account().get_keys().m_view_secret_key);
    const crypto::public_key local_pkey = get_multisig_signer_public_key(get_account().get_keys().m_spend_secret_key);
    for (size_t i = 0; i < secret_keys.size(); ++i)
    {
      if (secret_keys[i] == local_skey)
      {
        MDEBUG("Local key is present, ignoring");
        secret_keys[i] = secret_keys.back();
        public_keys[i] = public_keys.back();
        secret_keys.pop_back();
        public_keys.pop_back();
        --i;
      }
      else
      {
        THROW_WALLET_EXCEPTION_IF(public_keys[i] == local_pkey, error::wallet_internal_error,
            "Found local spend public key, but not local view secret key - something very weird");
      }
    }
  }

  std::string wallet2::make_multisig(const epee::wipeable_string &password,
    const std::vector<std::string> &info,
    uint32_t threshold)
  {
    std::vector<crypto::secret_key> secret_keys(info.size());
    std::vector<crypto::public_key> public_keys(info.size());
    unpack_multisig_info(info, public_keys, secret_keys);
    return make_multisig(password, secret_keys, public_keys, threshold);
  }

  bool wallet2::finalize_multisig(const epee::wipeable_string &password, const std::unordered_set<crypto::public_key> &pkeys, std::vector<crypto::public_key> signers)
  {
    bool ready;
    uint32_t threshold, total;
    if (!multisig(&ready, &threshold, &total))
    {
      MERROR("This is not a multisig wallet");
      return false;
    }
    if (ready)
    {
      MERROR("This multisig wallet is already finalized");
      return false;
    }
    if (threshold + 1 != total)
    {
      MERROR("finalize_multisig should only be used for N-1/N wallets, use exchange_multisig_keys instead");
      return false;
    }
    exchange_multisig_keys(password, pkeys, signers);
    return true;
  }

  bool wallet2::unpack_extra_multisig_info(const std::vector<std::string>& info,
    std::vector<crypto::public_key> &signers,
    std::unordered_set<crypto::public_key> &pkeys) const
  {
    // parse all multisig info
    signers.resize(info.size(), crypto::null_pkey);
    for (size_t i = 0; i < info.size(); ++i)
    {
        if (!verify_extra_multisig_info(info[i], pkeys, signers[i]))
        {
            return false;
        }
    }

    return true;
  }

  bool wallet2::finalize_multisig(const epee::wipeable_string &password, const std::vector<std::string> &info)
  {
    std::unordered_set<crypto::public_key> public_keys;
    std::vector<crypto::public_key> signers;
    if (!unpack_extra_multisig_info(info, signers, public_keys))
    {
      MERROR("Bad multisig info");
      return false;
    }

    return finalize_multisig(password, public_keys, signers);
  }

  std::string wallet2::get_multisig_info() const
  {
    // It's a signed package of private view key and public spend key
    const crypto::secret_key skey = cryptonote::get_multisig_blinded_secret_key(get_account().get_keys().m_view_secret_key);
    const crypto::public_key pkey = get_multisig_signer_public_key(get_account().get_keys().m_spend_secret_key);
    crypto::hash hash;

    std::string data;
    data += std::string((const char *)&skey, sizeof(crypto::secret_key));
    data += std::string((const char *)&pkey, sizeof(crypto::public_key));

    data.resize(data.size() + sizeof(crypto::signature));
    crypto::cn_fast_hash(data.data(), data.size() - sizeof(signature), hash);
    crypto::signature &signature = *(crypto::signature*)&data[data.size() - sizeof(crypto::signature)];
    crypto::generate_signature(hash, pkey, get_multisig_blinded_secret_key(get_account().get_keys().m_spend_secret_key), signature);

    return std::string("MultisigV1") + tools::base58::encode(data);
  }

  bool wallet2::verify_multisig_info(const std::string &data, crypto::secret_key &skey, crypto::public_key &pkey)
  {
    const size_t header_len = strlen("MultisigV1");
    if (data.size() < header_len || data.substr(0, header_len) != "MultisigV1")
    {
      MERROR("Multisig info header check error");
      return false;
    }
    std::string decoded;
    if (!tools::base58::decode(data.substr(header_len), decoded))
    {
      MERROR("Multisig info decoding error");
      return false;
    }
    if (decoded.size() != sizeof(crypto::secret_key) + sizeof(crypto::public_key) + sizeof(crypto::signature))
    {
      MERROR("Multisig info is corrupt");
      return false;
    }

    size_t offset = 0;
    skey = *(const crypto::secret_key*)(decoded.data() + offset);
    offset += sizeof(skey);
    pkey = *(const crypto::public_key*)(decoded.data() + offset);
    offset += sizeof(pkey);
    const crypto::signature &signature = *(const crypto::signature*)(decoded.data() + offset);

    crypto::hash hash;
    crypto::cn_fast_hash(decoded.data(), decoded.size() - sizeof(signature), hash);
    if (!crypto::check_signature(hash, pkey, signature))
    {
      MERROR("Multisig info signature is invalid");
      return false;
    }

    return true;
  }

  bool wallet2::verify_extra_multisig_info(const std::string &data, std::unordered_set<crypto::public_key> &pkeys, crypto::public_key &signer)
  {
    if (data.size() < MULTISIG_EXTRA_INFO_MAGIC.size() || data.substr(0, MULTISIG_EXTRA_INFO_MAGIC.size()) != MULTISIG_EXTRA_INFO_MAGIC)
    {
      MERROR("Multisig info header check error");
      return false;
    }
    std::string decoded;
    if (!tools::base58::decode(data.substr(MULTISIG_EXTRA_INFO_MAGIC.size()), decoded))
    {
      MERROR("Multisig info decoding error");
      return false;
    }
    if (decoded.size() < sizeof(crypto::public_key) + sizeof(crypto::signature))
    {
      MERROR("Multisig info is corrupt");
      return false;
    }
    if ((decoded.size() - (sizeof(crypto::public_key) + sizeof(crypto::signature))) % sizeof(crypto::public_key))
    {
      MERROR("Multisig info is corrupt");
      return false;
    }

    const size_t n_keys = (decoded.size() - (sizeof(crypto::public_key) + sizeof(crypto::signature))) / sizeof(crypto::public_key);
    size_t offset = 0;
    signer = *(const crypto::public_key*)(decoded.data() + offset);
    offset += sizeof(signer);
    const crypto::signature &signature = *(const crypto::signature*)(decoded.data() + offset + n_keys * sizeof(crypto::public_key));

    crypto::hash hash;
    crypto::cn_fast_hash(decoded.data(), decoded.size() - sizeof(signature), hash);
    if (!crypto::check_signature(hash, signer, signature))
    {
      MERROR("Multisig info signature is invalid");
      return false;
    }

    for (size_t n = 0; n < n_keys; ++n)
    {
      crypto::public_key mspk = *(const crypto::public_key*)(decoded.data() + offset);
      pkeys.insert(mspk);
      offset += sizeof(mspk);
    }

    return true;
  }

  bool wallet2::multisig(bool *ready, uint32_t *threshold, uint32_t *total) const
  {
    if (!m_multisig)
      return false;
    if (threshold)
      *threshold = m_multisig_threshold;
    if (total)
      *total = m_multisig_signers.size();
    if (ready)
      *ready = !(get_account().get_keys().m_account_address.m_spend_public_key == rct::rct2pk(rct::identity()));
    return true;
  }

  bool wallet2::has_multisig_partial_key_images() const
  {
    if (!m_multisig)
      return false;
    for (const auto &td: m_transfers)
      if (td.m_key_image_partial)
        return true;
    return false;
  }
  //----------------------------------------------------------------------------------------------------
  mms::multisig_wallet_state wallet2::get_multisig_wallet_state() const
  {
    mms::multisig_wallet_state state;
    state.nettype = m_nettype;
    state.multisig = multisig(&state.multisig_is_ready);
    state.has_multisig_partial_key_images = has_multisig_partial_key_images();
    state.multisig_rounds_passed = m_multisig_rounds_passed;
    state.num_transfer_details = m_transfers.size();
    if (state.multisig)
    {
      THROW_WALLET_EXCEPTION_IF(!m_original_keys_available, error::wallet_internal_error, "MMS use not possible because own original Xolentum address not available");
      state.address = m_original_address;
      state.view_secret_key = m_original_view_secret_key;
    }
    else
    {
      state.address = m_account.get_keys().m_account_address;
      state.view_secret_key = m_account.get_keys().m_view_secret_key;
    }
    state.mms_file=m_mms_file;
    return state;
  }
  //----------------------------------------------------------------------------------------------------
  std::string wallet2::save_multisig_tx(multisig_tx_set txs)
  {
    LOG_PRINT_L0("saving " << txs.m_ptx.size() << " multisig transactions");

    // txes generated, get rid of used k values
    for (size_t n = 0; n < txs.m_ptx.size(); ++n)
      for (size_t idx: txs.m_ptx[n].construction_data.selected_transfers)
        memwipe(m_transfers[idx].m_multisig_k.data(), m_transfers[idx].m_multisig_k.size() * sizeof(m_transfers[idx].m_multisig_k[0]));

    // zero out some data we don't want to share
    for (auto &ptx: txs.m_ptx)
    {
      for (auto &e: ptx.construction_data.sources)
        e.multisig_kLRki.k = rct::zero();
    }

    for (auto &ptx: txs.m_ptx)
    {
      // Get decrypted payment id from pending_tx
      ptx.construction_data = get_construction_data_with_decrypted_short_payment_id(ptx, m_account.get_device());
    }

    // save as binary
    std::ostringstream oss;
    binary_archive<true> ar(oss);
    try
    {
      if (!::serialization::serialize(ar, txs))
        return std::string();
    }
    catch (...)
    {
      return std::string();
    }
    LOG_PRINT_L2("Saving multisig unsigned tx data: " << oss.str());
    std::string ciphertext = encrypt_with_view_secret_key(oss.str());
    return std::string(MULTISIG_UNSIGNED_TX_PREFIX) + ciphertext;
  }
  //----------------------------------------------------------------------------------------------------
  bool wallet2::save_multisig_tx(const multisig_tx_set &txs, const std::string &filename)
  {
    std::string ciphertext = save_multisig_tx(txs);
    if (ciphertext.empty())
      return false;
    return save_to_file(filename, ciphertext);
  }
  //----------------------------------------------------------------------------------------------------
  wallet2::multisig_tx_set wallet2::make_multisig_tx_set(const std::vector<pending_tx>& ptx_vector) const
  {
    multisig_tx_set txs;
    txs.m_ptx = ptx_vector;

    for (const auto &msk: get_account().get_multisig_keys())
    {
      crypto::public_key pkey = get_multisig_signing_public_key(msk);
      for (auto &ptx: txs.m_ptx) for (auto &sig: ptx.multisig_sigs) sig.signing_keys.insert(pkey);
    }

    txs.m_signers.insert(get_multisig_signer_public_key());
    return txs;
  }

  std::string wallet2::save_multisig_tx(const std::vector<pending_tx>& ptx_vector)
  {
    return save_multisig_tx(make_multisig_tx_set(ptx_vector));
  }
  //----------------------------------------------------------------------------------------------------
  bool wallet2::save_multisig_tx(const std::vector<pending_tx>& ptx_vector, const std::string &filename)
  {
    std::string ciphertext = save_multisig_tx(ptx_vector);
    if (ciphertext.empty())
      return false;
    return save_to_file(filename, ciphertext);
  }
  //----------------------------------------------------------------------------------------------------
  bool wallet2::parse_multisig_tx_from_str(std::string multisig_tx_st, multisig_tx_set &exported_txs) const
  {
    const size_t magiclen = strlen(MULTISIG_UNSIGNED_TX_PREFIX);
    if (strncmp(multisig_tx_st.c_str(), MULTISIG_UNSIGNED_TX_PREFIX, magiclen))
    {
      LOG_PRINT_L0("Bad magic from multisig tx data");
      return false;
    }
    try
    {
      multisig_tx_st = decrypt_with_view_secret_key(std::string(multisig_tx_st, magiclen));
    }
    catch (const std::exception &e)
    {
      LOG_PRINT_L0("Failed to decrypt multisig tx data: " << e.what());
      return false;
    }
    bool loaded = false;
    try
    {
      std::istringstream iss(multisig_tx_st);
      binary_archive<false> ar(iss);
      if (::serialization::serialize(ar, exported_txs))
        if (::serialization::check_stream_state(ar))
          loaded = true;
    }
    catch (...) {}
    try
    {
      if (!loaded && m_load_deprecated_formats)
      {
        std::istringstream iss(multisig_tx_st);
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> exported_txs;
        loaded = true;
      }
    }
    catch(...) {}

    if (!loaded)
    {
      LOG_PRINT_L0("Failed to parse multisig tx data");
      return false;
    }

    // sanity checks
    for (const auto &ptx: exported_txs.m_ptx)
    {
      CHECK_AND_ASSERT_MES(ptx.selected_transfers.size() == ptx.tx.vin.size(), false, "Mismatched selected_transfers/vin sizes");
      for (size_t idx: ptx.selected_transfers)
        CHECK_AND_ASSERT_MES(idx < m_transfers.size(), false, "Transfer index out of range");
      CHECK_AND_ASSERT_MES(ptx.construction_data.selected_transfers.size() == ptx.tx.vin.size(), false, "Mismatched cd selected_transfers/vin sizes");
      for (size_t idx: ptx.construction_data.selected_transfers)
        CHECK_AND_ASSERT_MES(idx < m_transfers.size(), false, "Transfer index out of range");
      CHECK_AND_ASSERT_MES(ptx.construction_data.sources.size() == ptx.tx.vin.size(), false, "Mismatched sources/vin sizes");
    }

    return true;
  }
  //----------------------------------------------------------------------------------------------------
  bool wallet2::load_multisig_tx(cryptonote::blobdata s, multisig_tx_set &exported_txs, std::function<bool(const multisig_tx_set&)> accept_func)
  {
    if(!parse_multisig_tx_from_str(s, exported_txs))
    {
      LOG_PRINT_L0("Failed to parse multisig transaction from string");
      return false;
    }

    LOG_PRINT_L1("Loaded multisig tx unsigned data from binary: " << exported_txs.m_ptx.size() << " transactions");
    for (auto &ptx: exported_txs.m_ptx) LOG_PRINT_L0(cryptonote::obj_to_json_str(ptx.tx));

    if (accept_func && !accept_func(exported_txs))
    {
      LOG_PRINT_L1("Transactions rejected by callback");
      return false;
    }

    const bool is_signed = exported_txs.m_signers.size() >= m_multisig_threshold;
    if (is_signed)
    {
      for (const auto &ptx: exported_txs.m_ptx)
      {
        const crypto::hash txid = get_transaction_hash(ptx.tx);
        if (store_tx_info())
        {
          m_tx_keys[txid] = ptx.tx_key;
          m_additional_tx_keys[txid] = ptx.additional_tx_keys;
        }
      }
    }

    return true;
  }
  //----------------------------------------------------------------------------------------------------
  bool wallet2::load_multisig_tx_from_file(const std::string &filename, multisig_tx_set &exported_txs, std::function<bool(const multisig_tx_set&)> accept_func)
  {
    std::string s;
    boost::system::error_code errcode;

    if (!boost::filesystem::exists(filename, errcode))
    {
      LOG_PRINT_L0("File " << filename << " does not exist: " << errcode);
      return false;
    }
    if (!load_from_file(filename.c_str(), s))
    {
      LOG_PRINT_L0("Failed to load from " << filename);
      return false;
    }

    if (!load_multisig_tx(s, exported_txs, accept_func))
    {
      LOG_PRINT_L0("Failed to parse multisig tx data from " << filename);
      return false;
    }
    return true;
  }
  //----------------------------------------------------------------------------------------------------
  bool wallet2::sign_multisig_tx(multisig_tx_set &exported_txs, std::vector<crypto::hash> &txids)
  {
    THROW_WALLET_EXCEPTION_IF(exported_txs.m_ptx.empty(), error::wallet_internal_error, "No tx found");

    const crypto::public_key local_signer = get_multisig_signer_public_key();

    THROW_WALLET_EXCEPTION_IF(exported_txs.m_signers.find(local_signer) != exported_txs.m_signers.end(),
        error::wallet_internal_error, "Transaction already signed by this private key");
    THROW_WALLET_EXCEPTION_IF(exported_txs.m_signers.size() > m_multisig_threshold,
        error::wallet_internal_error, "Transaction was signed by too many signers");
    THROW_WALLET_EXCEPTION_IF(exported_txs.m_signers.size() == m_multisig_threshold,
        error::wallet_internal_error, "Transaction is already fully signed");

    txids.clear();

    // sign the transactions
    for (size_t n = 0; n < exported_txs.m_ptx.size(); ++n)
    {
      tools::wallet2::pending_tx &ptx = exported_txs.m_ptx[n];
      THROW_WALLET_EXCEPTION_IF(ptx.multisig_sigs.empty(), error::wallet_internal_error, "No signatures found in multisig tx");
      tools::wallet2::tx_construction_data &sd = ptx.construction_data;
      LOG_PRINT_L1(" " << (n+1) << ": " << sd.sources.size() << " inputs, mixin " << (sd.sources[0].outputs.size()-1) <<
          ", signed by " << exported_txs.m_signers.size() << "/" << m_multisig_threshold);
      cryptonote::transaction tx;
      rct::multisig_out msout = ptx.multisig_sigs.front().msout;
      auto sources = sd.sources;
      rct::RCTConfig rct_config = sd.rct_config;
      bool r = cryptonote::construct_tx_with_tx_key(m_account.get_keys(), m_subaddresses, sources, sd.splitted_dsts, ptx.change_dts.addr, sd.extra, tx, sd.unlock_time, ptx.tx_key, ptx.additional_tx_keys, sd.use_rct, rct_config, &msout, false,use_fork_rules(HF_VERSION_TX_POW_ENABLE, 5));
      THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sd.sources, sd.splitted_dsts, sd.unlock_time, m_nettype);

      THROW_WALLET_EXCEPTION_IF(get_transaction_prefix_hash (tx) != get_transaction_prefix_hash(ptx.tx),
          error::wallet_internal_error, "Transaction prefix does not match data");

      // Tests passed, sign
      std::vector<unsigned int> indices;
      for (const auto &source: sources)
        indices.push_back(source.real_output);

      for (auto &sig: ptx.multisig_sigs)
      {
        if (sig.ignore.find(local_signer) == sig.ignore.end())
        {
          ptx.tx.rct_signatures = sig.sigs;

          rct::keyV k;
          rct::key skey = rct::zero();
          auto wiper = epee::misc_utils::create_scope_leave_handler([&](){ memwipe(k.data(), k.size() * sizeof(k[0])); memwipe(&skey, sizeof(skey)); });

          for (size_t idx: sd.selected_transfers)
            k.push_back(get_multisig_k(idx, sig.used_L));

          for (const auto &msk: get_account().get_multisig_keys())
          {
            crypto::public_key pmsk = get_multisig_signing_public_key(msk);

            if (sig.signing_keys.find(pmsk) == sig.signing_keys.end())
            {
              sc_add(skey.bytes, skey.bytes, rct::sk2rct(msk).bytes);
              sig.signing_keys.insert(pmsk);
            }
          }
          THROW_WALLET_EXCEPTION_IF(!rct::signMultisig(ptx.tx.rct_signatures, indices, k, sig.msout, skey),
              error::wallet_internal_error, "Failed signing, transaction likely malformed");

          sig.sigs = ptx.tx.rct_signatures;
        }
      }

      const bool is_last = exported_txs.m_signers.size() + 1 >= m_multisig_threshold;
      if (is_last)
      {
        // when the last signature on a multisig tx is made, we select the right
        // signature to plug into the final tx
        bool found = false;
        for (const auto &sig: ptx.multisig_sigs)
        {
          if (sig.ignore.find(local_signer) == sig.ignore.end() && !keys_intersect(sig.ignore, exported_txs.m_signers))
          {
            THROW_WALLET_EXCEPTION_IF(found, error::wallet_internal_error, "More than one transaction is final");
            ptx.tx.rct_signatures = sig.sigs;
            found = true;
          }
        }
        THROW_WALLET_EXCEPTION_IF(!found, error::wallet_internal_error,
            "Final signed transaction not found: this transaction was likely made without our export data, so we cannot sign it");
        const crypto::hash txid = get_transaction_hash(ptx.tx);
        if (store_tx_info())
        {
          m_tx_keys[txid] = ptx.tx_key;
          m_additional_tx_keys[txid] = ptx.additional_tx_keys;
        }
        txids.push_back(txid);
      }
    }

    // txes generated, get rid of used k values
    for (size_t n = 0; n < exported_txs.m_ptx.size(); ++n)
      for (size_t idx: exported_txs.m_ptx[n].construction_data.selected_transfers)
        memwipe(m_transfers[idx].m_multisig_k.data(), m_transfers[idx].m_multisig_k.size() * sizeof(m_transfers[idx].m_multisig_k[0]));

    exported_txs.m_signers.insert(get_multisig_signer_public_key());

    return true;
  }
  //----------------------------------------------------------------------------------------------------
  bool wallet2::sign_multisig_tx_to_file(multisig_tx_set &exported_txs, const std::string &filename, std::vector<crypto::hash> &txids)
  {
    bool r = sign_multisig_tx(exported_txs, txids);
    if (!r)
      return false;
    return save_multisig_tx(exported_txs, filename);
  }
  //----------------------------------------------------------------------------------------------------
  bool wallet2::sign_multisig_tx_from_file(const std::string &filename, std::vector<crypto::hash> &txids, std::function<bool(const multisig_tx_set&)> accept_func)
  {
    multisig_tx_set exported_txs;
    if(!load_multisig_tx_from_file(filename, exported_txs))
      return false;

    if (accept_func && !accept_func(exported_txs))
    {
      LOG_PRINT_L1("Transactions rejected by callback");
      return false;
    }
    return sign_multisig_tx_to_file(exported_txs, filename, txids);
  }

  std::string wallet2::sign_multisig_participant(const std::string& data) const
  {
    CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");

    crypto::hash hash;
    crypto::cn_fast_hash(data.data(), data.size(), hash);
    const cryptonote::account_keys &keys = m_account.get_keys();
    crypto::signature signature;
    crypto::generate_signature(hash, get_multisig_signer_public_key(), keys.m_spend_secret_key, signature);
    return MULTISIG_SIGNATURE_MAGIC + tools::base58::encode(std::string((const char *)&signature, sizeof(signature)));
  }
  //----------------------------------------------------------------------------------------------------
  crypto::public_key wallet2::get_multisig_signer_public_key(const crypto::secret_key &spend_skey) const
  {
    crypto::public_key pkey;
    crypto::secret_key_to_public_key(get_multisig_blinded_secret_key(spend_skey), pkey);
    return pkey;
  }
  //----------------------------------------------------------------------------------------------------
  crypto::public_key wallet2::get_multisig_signer_public_key() const
  {
    CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");
    crypto::public_key signer;
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(get_account().get_keys().m_spend_secret_key, signer), "Failed to generate signer public key");
    return signer;
  }
  //----------------------------------------------------------------------------------------------------
  crypto::public_key wallet2::get_multisig_signing_public_key(const crypto::secret_key &msk) const
  {
    CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");
    crypto::public_key pkey;
    CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(msk, pkey), "Failed to derive public key");
    return pkey;
  }
  //----------------------------------------------------------------------------------------------------
  crypto::public_key wallet2::get_multisig_signing_public_key(size_t idx) const
  {
    CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");
    CHECK_AND_ASSERT_THROW_MES(idx < get_account().get_multisig_keys().size(), "Multisig signing key index out of range");
    return get_multisig_signing_public_key(get_account().get_multisig_keys()[idx]);
  }
  //----------------------------------------------------------------------------------------------------
  rct::key wallet2::get_multisig_k(size_t idx, const std::unordered_set<rct::key> &used_L) const
  {
    CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");
    CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "idx out of range");
    for (const auto &k: m_transfers[idx].m_multisig_k)
    {
      rct::key L;
      rct::scalarmultBase(L, k);
      if (used_L.find(L) != used_L.end())
        return k;
    }
    THROW_WALLET_EXCEPTION(tools::error::multisig_export_needed);
    return rct::zero();
  }
  //----------------------------------------------------------------------------------------------------
  rct::multisig_kLRki wallet2::get_multisig_kLRki(size_t n, const rct::key &k) const
  {
    CHECK_AND_ASSERT_THROW_MES(n < m_transfers.size(), "Bad m_transfers index");
    rct::multisig_kLRki kLRki;
    kLRki.k = k;
    cryptonote::generate_multisig_LR(m_transfers[n].get_public_key(), rct::rct2sk(kLRki.k), (crypto::public_key&)kLRki.L, (crypto::public_key&)kLRki.R);
    kLRki.ki = rct::ki2rct(m_transfers[n].m_key_image);
    return kLRki;
  }
  //----------------------------------------------------------------------------------------------------
  rct::multisig_kLRki wallet2::get_multisig_composite_kLRki(size_t n, const std::unordered_set<crypto::public_key> &ignore_set, std::unordered_set<rct::key> &used_L, std::unordered_set<rct::key> &new_used_L) const
  {
    CHECK_AND_ASSERT_THROW_MES(n < m_transfers.size(), "Bad transfer index");

    rct::multisig_kLRki kLRki = get_multisig_kLRki(n, rct::skGen());

    // pick a L/R pair from every other participant but one
    size_t n_signers_used = 1;
    for (const auto &p: m_transfers[n].m_multisig_info)
    {
      if (ignore_set.find(p.m_signer) != ignore_set.end())
        continue;

      for (const auto &lr: p.m_LR)
      {
        if (used_L.find(lr.m_L) != used_L.end())
          continue;
        used_L.insert(lr.m_L);
        new_used_L.insert(lr.m_L);
        rct::addKeys(kLRki.L, kLRki.L, lr.m_L);
        rct::addKeys(kLRki.R, kLRki.R, lr.m_R);
        ++n_signers_used;
        break;
      }
    }
    CHECK_AND_ASSERT_THROW_MES(n_signers_used >= m_multisig_threshold, "LR not found for enough participants");

    return kLRki;
  }
  //----------------------------------------------------------------------------------------------------
  crypto::key_image wallet2::get_multisig_composite_key_image(size_t n) const
  {
    CHECK_AND_ASSERT_THROW_MES(n < m_transfers.size(), "Bad output index");

    const transfer_details &td = m_transfers[n];
    const crypto::public_key tx_key = get_tx_pub_key_from_received_outs(td);
    const std::vector<crypto::public_key> additional_tx_keys = cryptonote::get_additional_tx_pub_keys_from_extra(td.m_tx);
    crypto::key_image ki;
    std::vector<crypto::key_image> pkis;
    for (const auto &info: td.m_multisig_info)
      for (const auto &pki: info.m_partial_key_images)
        pkis.push_back(pki);
    bool r = cryptonote::generate_multisig_composite_key_image(get_account().get_keys(), m_subaddresses, td.get_public_key(), tx_key, additional_tx_keys, td.m_internal_output_index, pkis, ki);
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
    return ki;
  }
  //----------------------------------------------------------------------------------------------------
  cryptonote::blobdata wallet2::export_multisig()
  {
    std::vector<tools::wallet2::multisig_info> info;

    const crypto::public_key signer = get_multisig_signer_public_key();

    info.resize(m_transfers.size());
    for (size_t n = 0; n < m_transfers.size(); ++n)
    {
      transfer_details &td = m_transfers[n];
      crypto::key_image ki;
      memwipe(td.m_multisig_k.data(), td.m_multisig_k.size() * sizeof(td.m_multisig_k[0]));
      info[n].m_LR.clear();
      info[n].m_partial_key_images.clear();

      for (size_t m = 0; m < get_account().get_multisig_keys().size(); ++m)
      {
        // we want to export the partial key image, not the full one, so we can't use td.m_key_image
        bool r = generate_multisig_key_image(get_account().get_keys(), m, td.get_public_key(), ki);
        CHECK_AND_ASSERT_THROW_MES(r, "Failed to generate key image");
        info[n].m_partial_key_images.push_back(ki);
      }

      // Wallet tries to create as many transactions as many signers combinations. We calculate the maximum number here as follows:
      // if we have 2/4 wallet with signers: A, B, C, D and A is a transaction creator it will need to pick up 1 signer from 3 wallets left.
      // That means counting combinations for excluding 2-of-3 wallets (k = total signers count - threshold, n = total signers count - 1).
      size_t nlr = tools::combinations_count(m_multisig_signers.size() - m_multisig_threshold, m_multisig_signers.size() - 1);
      for (size_t m = 0; m < nlr; ++m)
      {
        td.m_multisig_k.push_back(rct::skGen());
        const rct::multisig_kLRki kLRki = get_multisig_kLRki(n, td.m_multisig_k.back());
        info[n].m_LR.push_back({kLRki.L, kLRki.R});
      }

      info[n].m_signer = signer;
    }

    std::stringstream oss;
    binary_archive<true> ar(oss);
    CHECK_AND_ASSERT_THROW_MES(::serialization::serialize(ar, info), "Failed to serialize multisig data");

    const cryptonote::account_public_address &keys = get_account().get_keys().m_account_address;
    std::string header;
    header += std::string((const char *)&keys.m_spend_public_key, sizeof(crypto::public_key));
    header += std::string((const char *)&keys.m_view_public_key, sizeof(crypto::public_key));
    header += std::string((const char *)&signer, sizeof(crypto::public_key));
    std::string ciphertext = encrypt_with_view_secret_key(header + oss.str());

    return MULTISIG_EXPORT_FILE_MAGIC + ciphertext;
  }
  //----------------------------------------------------------------------------------------------------
  void wallet2::update_multisig_rescan_info(const std::vector<std::vector<rct::key>> &multisig_k, const std::vector<std::vector<tools::wallet2::multisig_info>> &info, size_t n)
  {
    CHECK_AND_ASSERT_THROW_MES(n < m_transfers.size(), "Bad index in update_multisig_info");
    CHECK_AND_ASSERT_THROW_MES(multisig_k.size() >= m_transfers.size(), "Mismatched sizes of multisig_k and info");

    MDEBUG("update_multisig_rescan_info: updating index " << n);
    transfer_details &td = m_transfers[n];
    td.m_multisig_info.clear();
    for (const auto &pi: info)
    {
      CHECK_AND_ASSERT_THROW_MES(n < pi.size(), "Bad pi size");
      td.m_multisig_info.push_back(pi[n]);
    }
    m_key_images.erase(td.m_key_image);
    td.m_key_image = get_multisig_composite_key_image(n);
    td.m_key_image_known = true;
    td.m_key_image_request = false;
    td.m_key_image_partial = false;
    td.m_multisig_k = multisig_k[n];
    m_key_images[td.m_key_image] = n;
  }
  //----------------------------------------------------------------------------------------------------
  size_t wallet2::import_multisig(std::vector<cryptonote::blobdata> blobs)
  {
    CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");

    std::vector<std::vector<tools::wallet2::multisig_info>> info;
    std::unordered_set<crypto::public_key> seen;
    for (cryptonote::blobdata &data: blobs)
    {
      const size_t magiclen = strlen(MULTISIG_EXPORT_FILE_MAGIC);
      THROW_WALLET_EXCEPTION_IF(data.size() < magiclen || memcmp(data.data(), MULTISIG_EXPORT_FILE_MAGIC, magiclen),
          error::wallet_internal_error, "Bad multisig info file magic in ");

      data = decrypt_with_view_secret_key(std::string(data, magiclen));

      const size_t headerlen = 3 * sizeof(crypto::public_key);
      THROW_WALLET_EXCEPTION_IF(data.size() < headerlen, error::wallet_internal_error, "Bad data size");

      const crypto::public_key &public_spend_key = *(const crypto::public_key*)&data[0];
      const crypto::public_key &public_view_key = *(const crypto::public_key*)&data[sizeof(crypto::public_key)];
      const crypto::public_key &signer = *(const crypto::public_key*)&data[2*sizeof(crypto::public_key)];
      const cryptonote::account_public_address &keys = get_account().get_keys().m_account_address;
      THROW_WALLET_EXCEPTION_IF(public_spend_key != keys.m_spend_public_key || public_view_key != keys.m_view_public_key,
          error::wallet_internal_error, "Multisig info is for a different account");
      if (get_multisig_signer_public_key() == signer)
      {
        MINFO("Multisig info from this wallet ignored");
        continue;
      }
      if (seen.find(signer) != seen.end())
      {
        MINFO("Duplicate multisig info ignored");
        continue;
      }
      seen.insert(signer);

      std::string body(data, headerlen);
      std::vector<tools::wallet2::multisig_info> i;

      bool loaded = false;
      try
      {
        std::istringstream iss(body);
        binary_archive<false> ar(iss);
        if (::serialization::serialize(ar, i))
          if (::serialization::check_stream_state(ar))
            loaded = true;
      }
      catch(...) {}
      if (!loaded && m_load_deprecated_formats)
      {
        std::istringstream iss(body);
        boost::archive::portable_binary_iarchive ar(iss);
        ar >> i;
        loaded = true;
      }
      CHECK_AND_ASSERT_THROW_MES(loaded, "Failed to load output data");

    for (const auto &e: i)
    {
      for (const auto &lr: e.m_LR)
      {
        CHECK_AND_ASSERT_THROW_MES(rct::isInMainSubgroup(lr.m_L), "Multisig value is not in the main subgroup");
        CHECK_AND_ASSERT_THROW_MES(rct::isInMainSubgroup(lr.m_R), "Multisig value is not in the main subgroup");
      }
      for (const auto &ki: e.m_partial_key_images)
      {
        CHECK_AND_ASSERT_THROW_MES(rct::isInMainSubgroup(rct::ki2rct(ki)), "Multisig partial key image is not in the main subgroup");
      }
    }

      MINFO(boost::format("%u outputs found") % boost::lexical_cast<std::string>(i.size()));
      info.push_back(std::move(i));
    }

    CHECK_AND_ASSERT_THROW_MES(info.size() + 1 <= m_multisig_signers.size() && info.size() + 1 >= m_multisig_threshold, "Wrong number of multisig sources");

    std::vector<std::vector<rct::key>> k;
    auto wiper = epee::misc_utils::create_scope_leave_handler([&](){for (auto &v: k) memwipe(v.data(), v.size() * sizeof(v[0]));});
    for (const auto &td: m_transfers)
      k.push_back(td.m_multisig_k);

    // how many outputs we're going to update
    size_t n_outputs = m_transfers.size();
    for (const auto &pi: info)
      if (pi.size() < n_outputs)
        n_outputs = pi.size();

    if (n_outputs == 0)
      return 0;

    // check signers are consistent
    for (const auto &pi: info)
    {
      CHECK_AND_ASSERT_THROW_MES(std::find(m_multisig_signers.begin(), m_multisig_signers.end(), pi[0].m_signer) != m_multisig_signers.end(),
          "Signer is not a member of this multisig wallet");
      for (size_t n = 1; n < n_outputs; ++n)
        CHECK_AND_ASSERT_THROW_MES(pi[n].m_signer == pi[0].m_signer, "Mismatched signers in imported multisig info");
    }

    // trim data we don't have info for from all participants
    for (auto &pi: info)
      pi.resize(n_outputs);

    // sort by signer
    if (!info.empty() && !info.front().empty())
    {
      std::sort(info.begin(), info.end(), [](const std::vector<tools::wallet2::multisig_info> &i0, const std::vector<tools::wallet2::multisig_info> &i1){ return memcmp(&i0[0].m_signer, &i1[0].m_signer, sizeof(i0[0].m_signer)) < 0; });
    }

    // first pass to determine where to detach the blockchain
    for (size_t n = 0; n < n_outputs; ++n)
    {
      const transfer_details &td = m_transfers[n];
      if (!td.m_key_image_partial)
        continue;
      MINFO("Multisig info importing from block height " << td.m_block_height);
      detach_blockchain(td.m_block_height);
      break;
    }

    for (size_t n = 0; n < n_outputs && n < m_transfers.size(); ++n)
    {
      update_multisig_rescan_info(k, info, n);
    }

    m_multisig_rescan_k = &k;
    m_multisig_rescan_info = &info;
    try
    {

      refresh(false);
    }
    catch (...)
    {
      m_multisig_rescan_info = NULL;
      m_multisig_rescan_k = NULL;
      throw;
    }
    m_multisig_rescan_info = NULL;
    m_multisig_rescan_k = NULL;

    return n_outputs;
  }
}
