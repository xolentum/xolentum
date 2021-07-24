// Copyright (c) 2014-2020, The Monero Project
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

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"
#include <boost/system/error_code.hpp>
#include <boost/filesystem.hpp>
#include <functional>
#include <vector>

using namespace epee;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  /**
   * @brief struct for loading a checkpoint from json
   */
  struct t_hashline
  {
    uint64_t height; //!< the height of the checkpoint
    std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
          KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
  };

  /**
   * @brief struct for loading many checkpoints from json
   */
  struct t_hash_json {
    std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
  };

  //---------------------------------------------------------------------------
  checkpoints::checkpoints()
  {
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str, const std::string& difficulty_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r = epee::string_tools::hex_to_pod(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    // return false if adding at a height we already have AND the hash is different
    if (m_points.count(height))
    {
      CHECK_AND_ASSERT_MES(h == m_points[height], false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    m_points[height] = h;
    if (!difficulty_str.empty())
    {
      try
      {
        difficulty_type difficulty(difficulty_str);
        if (m_difficulty_points.count(height))
        {
          CHECK_AND_ASSERT_MES(difficulty == m_difficulty_points[height], false, "Difficulty checkpoint at given height already exists, and difficulty for new checkpoint was different!");
        }
        m_difficulty_points[height] = difficulty;
      }
      catch (...)
      {
        LOG_ERROR("Failed to parse difficulty checkpoint: " << difficulty_str);
        return false;
      }
    }
    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool& is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    is_a_checkpoint = it != m_points.end();
    if(!is_a_checkpoint)
      return true;

    if(it->second == h)
    {
      MINFO("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
      return true;
    }else
    {
      MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH: " << it->second << ", FETCHED HASH: " << h);
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h) const
  {
    bool ignored;
    return check_block(height, h, ignored);
  }
  //---------------------------------------------------------------------------
  //FIXME: is this the desired behavior?
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);
    // Is blockchain_height before the first checkpoint?
    if (it == m_points.begin())
      return true;

    --it;
    uint64_t checkpoint_height = it->first;
    return checkpoint_height < block_height;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    if (m_points.empty())
      return 0;
    return m_points.rbegin()->first;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, crypto::hash>& checkpoints::get_points() const
  {
    return m_points;
  }
  //---------------------------------------------------------------------------
  const std::map<uint64_t, difficulty_type>& checkpoints::get_difficulty_points() const
  {
    return m_difficulty_points;
  }
  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        CHECK_AND_ASSERT_MES(pt.second == m_points.at(pt.first), false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

  bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    if (nettype == TESTNET)
    {
      return true;
    }
    if (nettype == STAGENET)
    {
      return true;
    }
    ADD_CHECKPOINT(0, "8e9a672e45ccec5e20860cbfebc225310364d648dc87561a095d80a15cfc25d4");
    ADD_CHECKPOINT(2500, "1ab186c3ed7a337a533144ccbafe60dc745cd403f3e3841ccba8fd253e6adda3");
    ADD_CHECKPOINT(5000, "18bf499d59686ea575a1abc24fb136f1343edcea6a96c791a4e49719854b9db2");
    ADD_CHECKPOINT(7500, "ff4cd427ddb156914333a775921e485b9ef1e9c3e0cbce4a069e172ecea0963a");
    ADD_CHECKPOINT(10000, "c458227a0a5f2e82db9a9ceebdcecdf92936bddcc12c022dea1a295831dcbaa0");
    ADD_CHECKPOINT(12500, "0acc67e12b372db11d6483349b7b91f79a4a6dc81bdbf6ab7954f1386d27e5ea");
    ADD_CHECKPOINT(15000, "275eb63397c15292ca0c7b216000df3bc773c808faaf3f899e7b5027964df0eb");
    ADD_CHECKPOINT(17500, "d70c5d8e2705c2d2ee8e7acc62e3a75b0329228addc7468b3443276902488245");
    ADD_CHECKPOINT(20000, "af4db1be08eab4173f51b74fe9c3b55be3e2c56e41975449e7e507a3ad4fc0c0");
    ADD_CHECKPOINT(22500,"981dd60d18faaabe4bea1ba30af249398291e9aae1c67f04efb4f2bc7e704609")
    ADD_CHECKPOINT(25000,"8101ebca14d9537454259ead5f24cceabf834617f9ebe8694f2295f617ee08e7")
    ADD_CHECKPOINT(27500,"dc8e14a5978e31db0d0c3e16f7f4699255a68a76068ac45e2719695852c28a8e")
    ADD_CHECKPOINT(30000,"132346cec89659dbc26b95a0a01daa26f4b211cb0e6e198f762c7ff5e022b484")
    ADD_CHECKPOINT(32500,"3206d0d4b0b0eb73c07825065ee34978a4adf04fc9de6591e810cdb369551d66")
    ADD_CHECKPOINT(35000,"3d177af49c1665596ca503f7fead5849a3be7ba76704bd47c8dce46f175fe43a")
    ADD_CHECKPOINT(37500,"cc293a36c700e01428367791e68fb4b69033d8cd229a389b2d30886279d8df92")
    ADD_CHECKPOINT(40000,"0e7fce4ace412a5b2034bda1e81e4ea2b3f879ee9f301e9e65f4d11f3babf970")
    ADD_CHECKPOINT(42500,"3a2c4b666cbda63338d214a870b12104458859558e61701d0f45cab2cb4e9239")
    ADD_CHECKPOINT(45000,"dd7ac4546f478421f504a0db6bbfd70506a27beaad9cf18acd96e2b6ff3acd75")
    ADD_CHECKPOINT(47500,"61c109311a8616546568f01ce4463c00774856c026b0d52625cca7ad4fe5dec9")
    ADD_CHECKPOINT(50000,"2cd6747b405ef5103e64deb70291ddde779d704848b052d87646c6e253cf10ff")
    ADD_CHECKPOINT(52500,"8809eef6dbaef68a3ec8c9c30fdca7824eabb078a086a3dc7796305e68430c5e")
    ADD_CHECKPOINT(55000,"c29bccc4d73595a043a4a0b8b17204242bad5f05b333134a1363f092681a2f6b")
    ADD_CHECKPOINT(57500,"e0b5b76e224e98fe52742a8fbea1c701187e1dae5e72adc1ef86856a82a52823")
    ADD_CHECKPOINT(60000,"39d5c5fbb4edc6fbbffd41b5266f5640370a2fca5a78fb95662ce1347307143e")
    ADD_CHECKPOINT(62500,"e452e70a221915e7669c6bd04639c96cf75d046cab1066f482995230108da83b")
    ADD_CHECKPOINT(65000,"a98b26659cf32b05dcd1ad4c33b3e8e35da2e88e82866560a9882986e2ea7264")
    ADD_CHECKPOINT(67500,"43abe4322de2ccd5eed10b7d99084a6a6fa83d47fc7b38bc0d1d35ae870e64ac")
    ADD_CHECKPOINT(70000,"6c3991f5ed817501f382d6565a423cedf2b7c65296daf385cfc8bed63726c5e3")
    ADD_CHECKPOINT(72500,"bbbb3f259d2eb3ec87652b7ed257e4a8dec0de4465534b0cf60f016fb8de2edd")
    ADD_CHECKPOINT(75000,"d66e0e82e597111e201a22a97f798243e9ca8d272f4af9e99364ffeb11da68da")
    ADD_CHECKPOINT(77500,"980d85100d52d5ca33c4e08b02e2d611b409323a9c57572ced8fcff196da2f88")
    ADD_CHECKPOINT(80000,"a49986965306847c6408adcb9ce11c2f4748cab9ddac9c1de55c6de50106c253")
    ADD_CHECKPOINT(82500,"c2b394c0feaa36848ea2a70f01149a446205a4b883ca9aad3d3dfcd647873d10")
    ADD_CHECKPOINT(85000,"16e4fa27f88f3e884f5dd32571d685c2e0db3c1c79f1c581a69ce6fd3a2107bd")
    ADD_CHECKPOINT(87500,"a299c1ffb001e33d48c563d824e11d5ea42068af315e72f0d2ec53f32250ba25")
    ADD_CHECKPOINT(90000,"fb316cb5e15792fd7ed166e0fb8de58295dd8e202421d012001dab11160110cb")
    ADD_CHECKPOINT(92500,"ab3b7bfa9781c20a79678abe6e1a708dd4137575d1b5dff8271a47c767fd7d9e")
    ADD_CHECKPOINT(95000,"781d4fde9145682ad25a98272a0eba1eeca1051b139ba4c4c36b92dc08a82f80")
    ADD_CHECKPOINT(97500,"a1af8a759a6ce4ad0098e8dfc6d71aa2302875e3eb510733615b7b75f8c25542")
    ADD_CHECKPOINT(100000,"7210cd1384dbb2987ddb06cfe60d8974a4216fa9b0feeb4f94d47dc2a11487a1")
    ADD_CHECKPOINT(102500,"5a68d0345ec48a186660e3fa817a42d3ecca42393d40bd32deb85f7cd6871bd4")
    ADD_CHECKPOINT(105000,"1a60857d875e85f1507271930e1b261f86761c30851a451b974562512e460fe0")
    ADD_CHECKPOINT(107500,"13129c8087cf7be2d9a9fc3d8a576eae03c2a74b5213ef793db7286b44b7345d")
    ADD_CHECKPOINT(110000,"9ca96c7e587e070803496d853a9dd2e4056d0c59d5a30e662da59b99aef329c1")
    ADD_CHECKPOINT(112500,"df3fb8c82d8cd4b3886447d27619e6dec3d07ed906545b23fb1df3bc67ceba91")
    ADD_CHECKPOINT(115000,"3325fd2fae428ee90004f5ebca5558b3941e49c016e548ff90880f2f44e7b402")
    ADD_CHECKPOINT(117500,"9c26540826c08f1a4ce2049286202dfeb972cab7c9ba5e118da0b72e413fb526")
    ADD_CHECKPOINT(120000,"cc4d175ac0b2fcc8b907e4122428b995f67399efc14e6dc68c1a4ebe3cb3cbb9")
    ADD_CHECKPOINT(122500,"b3068f90f766884d7d900c94a25c33b61d66fc9ea6768c19a44e548d45a165e3")
    ADD_CHECKPOINT(125000,"2d2dd543ba1b0010f697c4d87a1b8bd3d4748b4a5d8b8d4380ff7e15d1bceecb")
    ADD_CHECKPOINT(127500,"fc7079150c09da72275867d70c17955fcb4100ca45936f2f453dc24583885759")
    ADD_CHECKPOINT(130000,"0d5934802141205464c710b6755761726bd247181f518a135bb4c7efb0880e0a")
    ADD_CHECKPOINT(132500,"8d0cc0be0b36e1b932f7df853e0ce3497e0898a6554bf3d529d70f3780ee9fe7")
    ADD_CHECKPOINT(135000,"9753499897e175cfb0f67da0f9bbb797474bbb15e1e1d754f53f6eed87e1945a")
    ADD_CHECKPOINT(137500,"df8204e0adb52b43939d36e8f269d455c81a958012d4a18ed46045cb54ef9366")
    ADD_CHECKPOINT(140000,"6b517beeeef034c4bd61f446e4aa70d0d7b201d8a5b02638bbb336773231d772")
    ADD_CHECKPOINT(142500,"748c90bc21e9d949cbad4189b75a775e15e2d90259aee4e772c2ef93cc72cbef")
    ADD_CHECKPOINT(145000,"321e3aa2a9a462e3ced7c5f0bf3ea196bf44baeb049a3a7176628dad64fbf0fc")
    ADD_CHECKPOINT(147500,"15c249e56aa817ebc000e9d015d18469f66f3c5e9cb78172b92758a09ec5926e")
    ADD_CHECKPOINT(150000,"bad04be143f807b67a98a59b197c00ffdd316391558f4c8be19d090075b48c1a")
    ADD_CHECKPOINT(152500,"9df76414d954316e51b2b576b0327cf075d6385f4d2a8e9780a289fa04fa37ee")
    ADD_CHECKPOINT(155000,"cac2e2aded97e80ca3253c7c50b5268e9559e86c294ca30edebda3f20476a13b")
    ADD_CHECKPOINT(157500,"86d5c51ffc1665b036e97bcb0f477d1275dc74253aa10c1342d66cafa1d941f9")
    ADD_CHECKPOINT(160000,"4afa96d9b506b2511593ed68b9a90eff41923fef6d7a5c74a54fcd62c62f283a")
    ADD_CHECKPOINT(162500,"4c3a6b201cda3b49a150df1f46dccfd2c2ef2dddb5297899314ed7086f6db268")
    ADD_CHECKPOINT(165000,"0ebee84f1d5724d579ac9df9fce7d551636e1144238baa800a22007a47653cce")
    ADD_CHECKPOINT(167500,"de86123b5c944afc50526421c4a2824defa41048d9b7b602ab67aeb035d0bbe1")
    ADD_CHECKPOINT(170000,"f8bc1d5cc25b593e6bd036ddf94e5e5026bf0318d414a97a40a75d57372072c6")
    ADD_CHECKPOINT(172500,"1f2a0fdccbea38b3e2c00f45de7b18f909176e5a62434165432a7e68502c52b2")
    ADD_CHECKPOINT(175000,"1b43356659e961e63706b9d5f7a3333f7ac30858d6f950f2feafcc33709f0b81")
    ADD_CHECKPOINT(177500,"a9d09580db05ba42af0228814efcf04922456e853960137895a0733b824cf1e8")
    ADD_CHECKPOINT(180000,"442fb58033066115dc893b5944f0ff81dbd254e9c73ec2c59987e9c4573cbc31")
    ADD_CHECKPOINT(182500,"356d3de36321722eadc1f2859f2ad9a09ee21fe240fca1482bc3f2e60e3af9f4")
    ADD_CHECKPOINT(185000,"e016f776fa031ffa19d288b0ab328750a3c659f3fefd0065fe5634607c60a31d")
    ADD_CHECKPOINT(187500,"55d669c0ce5da3ece5cc467a52624af6503c84db875a8fda283acd6c1039f5c1")
    ADD_CHECKPOINT(190000,"f36635f81d6d57ee392dd7faf20cf85122c0a9e6fa131d7e6bfa19ea7f63b9cc")
    ADD_CHECKPOINT(192500,"da2bdf5d5b8c42b9c13ac69bbb404dcbc9f30f8a4dddd35d11aec322aef8c6df")
    ADD_CHECKPOINT(195000,"c057c7806b921b7019bcce1bf44bc3cf21b94a1d846a7cd49ba6de0cf72e9e0e")
    ADD_CHECKPOINT(197500,"287c899e64f689d3df1bed21a64a758f6470751b16d00a873816375167065924")
    ADD_CHECKPOINT(200000,"6e0fd80c8938372f9b7c40dc393cda9ad6c1354208b04e235f91a174a3a84265")
    ADD_CHECKPOINT(202500,"cfa01be8ab14aa2c5639a859196af10f2719f0fc7d16aaa339a6413a47d51d4d")
    ADD_CHECKPOINT(205000,"78a9a4403836e0bfc7401aabf5922f47920b279ed74cb189ece16169f9753629")
    ADD_CHECKPOINT(207500,"093142fa8a9b18046a0bc7d48f5ce77c08860df864634e5480d1ba3e220d7105")
    ADD_CHECKPOINT(210000,"720693c313d58e2ca15ebf5726f3d79168e7df26819f9d64b50001c325db8f02")
    ADD_CHECKPOINT(212500,"837794a0daa590e40a2edb86b97316f3357142527260e215a94dc9e5107dbd1a")
    ADD_CHECKPOINT(215000,"02bd0e72d746508fff231d6fa37f7ec45cc57398fb5fcc42885ce97006a5707f")
    ADD_CHECKPOINT(217500,"3d2b63fccaff8c48da8656e81e3f14e59f7c29c818eb2d7844a4fee0a9b8dfaa")

    return true;
  }

  bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }
    for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
	LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
	std::string blockhash = it->hash;
	LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
	ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(network_type nettype)
  {
    std::vector<std::string> records;

    // All four MoneroPulse domains have DNSSEC on and valid
    static const std::vector<std::string> dns_urls = {
      "checkpoint.xol.junichi2000.jp.eu.org",
      "checkpoint.xolentum.org",
      "checkpoint.xol-pulse.jp.eu.org"
    };

    static const std::vector<std::string> testnet_dns_urls = { };

    static const std::vector<std::string> stagenet_dns_urls = { };

    if (!tools::dns_utils::load_txt_records_from_dns(records, nettype == TESTNET ? testnet_dns_urls : nettype == STAGENET ? stagenet_dns_urls : dns_urls))
      return true; // why true ?

    for (const auto& record : records)
    {
      auto pos = record.find(":");
      if (pos != std::string::npos)
      {
        uint64_t height;
        crypto::hash hash;

        // parse the first part as uint64_t,
        // if this fails move on to the next record
        std::stringstream ss(record.substr(0, pos));
        if (!(ss >> height))
        {
    continue;
        }

        // parse the second part as crypto::hash,
        // if this fails move on to the next record
        std::string hashStr = record.substr(pos + 1);
        if (!epee::string_tools::hex_to_pod(hashStr, hash))
        {
    continue;
        }

        ADD_CHECKPOINT(height, hashStr);
      }
    }
    return false;
  }

  bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(nettype);
    }

    return result;
  }
}
