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
	ADD_CHECKPOINT(22500, "981dd60d18faaabe4bea1ba30af249398291e9aae1c67f04efb4f2bc7e704609");
	ADD_CHECKPOINT(25000, "8101ebca14d9537454259ead5f24cceabf834617f9ebe8694f2295f617ee08e7");
	ADD_CHECKPOINT(27500, "dc8e14a5978e31db0d0c3e16f7f4699255a68a76068ac45e2719695852c28a8e");
	ADD_CHECKPOINT(30000, "132346cec89659dbc26b95a0a01daa26f4b211cb0e6e198f762c7ff5e022b484");
	ADD_CHECKPOINT(32500, "3206d0d4b0b0eb73c07825065ee34978a4adf04fc9de6591e810cdb369551d66");
	ADD_CHECKPOINT(35000, "3d177af49c1665596ca503f7fead5849a3be7ba76704bd47c8dce46f175fe43a");
	ADD_CHECKPOINT(37500, "cc293a36c700e01428367791e68fb4b69033d8cd229a389b2d30886279d8df92");
	ADD_CHECKPOINT(40000, "0e7fce4ace412a5b2034bda1e81e4ea2b3f879ee9f301e9e65f4d11f3babf970");
	ADD_CHECKPOINT(42500, "3a2c4b666cbda63338d214a870b12104458859558e61701d0f45cab2cb4e9239");
	ADD_CHECKPOINT(45000, "dd7ac4546f478421f504a0db6bbfd70506a27beaad9cf18acd96e2b6ff3acd75");
	ADD_CHECKPOINT(47500, "61c109311a8616546568f01ce4463c00774856c026b0d52625cca7ad4fe5dec9");
	ADD_CHECKPOINT(50000, "2cd6747b405ef5103e64deb70291ddde779d704848b052d87646c6e253cf10ff");
	ADD_CHECKPOINT(52500, "8809eef6dbaef68a3ec8c9c30fdca7824eabb078a086a3dc7796305e68430c5e");
	ADD_CHECKPOINT(55000, "c29bccc4d73595a043a4a0b8b17204242bad5f05b333134a1363f092681a2f6b");
	ADD_CHECKPOINT(57500, "e0b5b76e224e98fe52742a8fbea1c701187e1dae5e72adc1ef86856a82a52823");
	ADD_CHECKPOINT(60000, "39d5c5fbb4edc6fbbffd41b5266f5640370a2fca5a78fb95662ce1347307143e");
	ADD_CHECKPOINT(62500, "e452e70a221915e7669c6bd04639c96cf75d046cab1066f482995230108da83b");
	ADD_CHECKPOINT(65000, "a98b26659cf32b05dcd1ad4c33b3e8e35da2e88e82866560a9882986e2ea7264");
	ADD_CHECKPOINT(67500, "43abe4322de2ccd5eed10b7d99084a6a6fa83d47fc7b38bc0d1d35ae870e64ac");
	ADD_CHECKPOINT(70000, "6c3991f5ed817501f382d6565a423cedf2b7c65296daf385cfc8bed63726c5e3");
	ADD_CHECKPOINT(72500, "bbbb3f259d2eb3ec87652b7ed257e4a8dec0de4465534b0cf60f016fb8de2edd");
	ADD_CHECKPOINT(75000, "d66e0e82e597111e201a22a97f798243e9ca8d272f4af9e99364ffeb11da68da");
	ADD_CHECKPOINT(77500, "980d85100d52d5ca33c4e08b02e2d611b409323a9c57572ced8fcff196da2f88");
	ADD_CHECKPOINT(80000, "a49986965306847c6408adcb9ce11c2f4748cab9ddac9c1de55c6de50106c253");
	ADD_CHECKPOINT(82500, "c2b394c0feaa36848ea2a70f01149a446205a4b883ca9aad3d3dfcd647873d10");
	ADD_CHECKPOINT(85000, "16e4fa27f88f3e884f5dd32571d685c2e0db3c1c79f1c581a69ce6fd3a2107bd");
	ADD_CHECKPOINT(87500, "a299c1ffb001e33d48c563d824e11d5ea42068af315e72f0d2ec53f32250ba25");
	ADD_CHECKPOINT(90000, "fb316cb5e15792fd7ed166e0fb8de58295dd8e202421d012001dab11160110cb");
	ADD_CHECKPOINT(92500, "ab3b7bfa9781c20a79678abe6e1a708dd4137575d1b5dff8271a47c767fd7d9e");
	ADD_CHECKPOINT(95000, "781d4fde9145682ad25a98272a0eba1eeca1051b139ba4c4c36b92dc08a82f80");
	ADD_CHECKPOINT(97500, "a1af8a759a6ce4ad0098e8dfc6d71aa2302875e3eb510733615b7b75f8c25542");
	ADD_CHECKPOINT(100000, "7210cd1384dbb2987ddb06cfe60d8974a4216fa9b0feeb4f94d47dc2a11487a1");
	ADD_CHECKPOINT(102500, "5a68d0345ec48a186660e3fa817a42d3ecca42393d40bd32deb85f7cd6871bd4");
	ADD_CHECKPOINT(105000, "1a60857d875e85f1507271930e1b261f86761c30851a451b974562512e460fe0");
	ADD_CHECKPOINT(107500, "13129c8087cf7be2d9a9fc3d8a576eae03c2a74b5213ef793db7286b44b7345d");
	ADD_CHECKPOINT(110000, "9ca96c7e587e070803496d853a9dd2e4056d0c59d5a30e662da59b99aef329c1");
	ADD_CHECKPOINT(112500, "df3fb8c82d8cd4b3886447d27619e6dec3d07ed906545b23fb1df3bc67ceba91");
	ADD_CHECKPOINT(115000, "3325fd2fae428ee90004f5ebca5558b3941e49c016e548ff90880f2f44e7b402");
	ADD_CHECKPOINT(117500, "9c26540826c08f1a4ce2049286202dfeb972cab7c9ba5e118da0b72e413fb526");
	ADD_CHECKPOINT(120000, "cc4d175ac0b2fcc8b907e4122428b995f67399efc14e6dc68c1a4ebe3cb3cbb9");
	ADD_CHECKPOINT(122500, "b3068f90f766884d7d900c94a25c33b61d66fc9ea6768c19a44e548d45a165e3");
	ADD_CHECKPOINT(125000, "2d2dd543ba1b0010f697c4d87a1b8bd3d4748b4a5d8b8d4380ff7e15d1bceecb");
	ADD_CHECKPOINT(127500, "fc7079150c09da72275867d70c17955fcb4100ca45936f2f453dc24583885759");
	ADD_CHECKPOINT(130000, "0d5934802141205464c710b6755761726bd247181f518a135bb4c7efb0880e0a");
	ADD_CHECKPOINT(132500, "8d0cc0be0b36e1b932f7df853e0ce3497e0898a6554bf3d529d70f3780ee9fe7");
	ADD_CHECKPOINT(135000, "9753499897e175cfb0f67da0f9bbb797474bbb15e1e1d754f53f6eed87e1945a");
	ADD_CHECKPOINT(137500, "df8204e0adb52b43939d36e8f269d455c81a958012d4a18ed46045cb54ef9366");
	ADD_CHECKPOINT(140000, "6b517beeeef034c4bd61f446e4aa70d0d7b201d8a5b02638bbb336773231d772");
	ADD_CHECKPOINT(142500, "748c90bc21e9d949cbad4189b75a775e15e2d90259aee4e772c2ef93cc72cbef");
	ADD_CHECKPOINT(145000, "321e3aa2a9a462e3ced7c5f0bf3ea196bf44baeb049a3a7176628dad64fbf0fc");
	ADD_CHECKPOINT(147500, "15c249e56aa817ebc000e9d015d18469f66f3c5e9cb78172b92758a09ec5926e");
	ADD_CHECKPOINT(150000, "bad04be143f807b67a98a59b197c00ffdd316391558f4c8be19d090075b48c1a");
	ADD_CHECKPOINT(152500, "9df76414d954316e51b2b576b0327cf075d6385f4d2a8e9780a289fa04fa37ee");
	ADD_CHECKPOINT(155000, "cac2e2aded97e80ca3253c7c50b5268e9559e86c294ca30edebda3f20476a13b");
	ADD_CHECKPOINT(157500, "86d5c51ffc1665b036e97bcb0f477d1275dc74253aa10c1342d66cafa1d941f9");
	ADD_CHECKPOINT(160000, "4afa96d9b506b2511593ed68b9a90eff41923fef6d7a5c74a54fcd62c62f283a");
	ADD_CHECKPOINT(162500, "4c3a6b201cda3b49a150df1f46dccfd2c2ef2dddb5297899314ed7086f6db268");
	ADD_CHECKPOINT(165000, "0ebee84f1d5724d579ac9df9fce7d551636e1144238baa800a22007a47653cce");
	ADD_CHECKPOINT(167500, "de86123b5c944afc50526421c4a2824defa41048d9b7b602ab67aeb035d0bbe1");
	ADD_CHECKPOINT(170000, "f8bc1d5cc25b593e6bd036ddf94e5e5026bf0318d414a97a40a75d57372072c6");
	ADD_CHECKPOINT(172500, "1f2a0fdccbea38b3e2c00f45de7b18f909176e5a62434165432a7e68502c52b2");
	ADD_CHECKPOINT(175000, "1b43356659e961e63706b9d5f7a3333f7ac30858d6f950f2feafcc33709f0b81");
	ADD_CHECKPOINT(177500, "a9d09580db05ba42af0228814efcf04922456e853960137895a0733b824cf1e8");
	ADD_CHECKPOINT(180000, "442fb58033066115dc893b5944f0ff81dbd254e9c73ec2c59987e9c4573cbc31");
	ADD_CHECKPOINT(182500, "356d3de36321722eadc1f2859f2ad9a09ee21fe240fca1482bc3f2e60e3af9f4");
	ADD_CHECKPOINT(185000, "e016f776fa031ffa19d288b0ab328750a3c659f3fefd0065fe5634607c60a31d");
	ADD_CHECKPOINT(187500, "55d669c0ce5da3ece5cc467a52624af6503c84db875a8fda283acd6c1039f5c1");
	ADD_CHECKPOINT(190000, "f36635f81d6d57ee392dd7faf20cf85122c0a9e6fa131d7e6bfa19ea7f63b9cc");
	ADD_CHECKPOINT(192500, "da2bdf5d5b8c42b9c13ac69bbb404dcbc9f30f8a4dddd35d11aec322aef8c6df");
	ADD_CHECKPOINT(195000, "c057c7806b921b7019bcce1bf44bc3cf21b94a1d846a7cd49ba6de0cf72e9e0e");
	ADD_CHECKPOINT(197500, "287c899e64f689d3df1bed21a64a758f6470751b16d00a873816375167065924");
	ADD_CHECKPOINT(200000, "6e0fd80c8938372f9b7c40dc393cda9ad6c1354208b04e235f91a174a3a84265");
	ADD_CHECKPOINT(202500, "cfa01be8ab14aa2c5639a859196af10f2719f0fc7d16aaa339a6413a47d51d4d");
	ADD_CHECKPOINT(205000, "78a9a4403836e0bfc7401aabf5922f47920b279ed74cb189ece16169f9753629");
	ADD_CHECKPOINT(207500, "093142fa8a9b18046a0bc7d48f5ce77c08860df864634e5480d1ba3e220d7105");
	ADD_CHECKPOINT(210000, "720693c313d58e2ca15ebf5726f3d79168e7df26819f9d64b50001c325db8f02");
	ADD_CHECKPOINT(212500, "837794a0daa590e40a2edb86b97316f3357142527260e215a94dc9e5107dbd1a");
	ADD_CHECKPOINT(215000, "02bd0e72d746508fff231d6fa37f7ec45cc57398fb5fcc42885ce97006a5707f");
	ADD_CHECKPOINT(217500, "3d2b63fccaff8c48da8656e81e3f14e59f7c29c818eb2d7844a4fee0a9b8dfaa");
	ADD_CHECKPOINT(220000, "ec7aa3f8fdf364c921cf2394e52b5f1fa690cbe39ae5c2550bb46a839a1de1da");
	ADD_CHECKPOINT(222500, "e98688189ac35f91aa7e874f1ab1b578bf12c0e21953b1bb627bd53e3fc1929b");
	ADD_CHECKPOINT(225000, "fde66aa90255f300ed1a0aba13e2ce594d07588e8404f257317eb44c4528f12d");
	ADD_CHECKPOINT(227500, "baa16d1b516afba936121725a6a231883309717fa91baeeccaa12c416379397e");
	ADD_CHECKPOINT(230000, "15a55bb4143fa774046096997eef8263343907c9c4908050a94148089c6f2fd6");
	ADD_CHECKPOINT(232500, "ef66012bb2ef32cd75f8c28a46d37e868c16b2770c3fdd9b6f9185406b390097");
	ADD_CHECKPOINT(235000, "824e96a69621757b4c0e72debdafade1c7b8bc78e806d787c5eda1d7cd1fe365");
	ADD_CHECKPOINT(237500, "eef7b6070860a71dd25c9881ec233b073b0558b669273cb596f587835bfb3df2");
	ADD_CHECKPOINT(240000, "156e951a998a44bbacc2fb988d8f9b18c0d0cd65782476d11e2ed8331edb275b");
	ADD_CHECKPOINT(242500, "d1b15aeb129ef54bd684b3e98e35e5ee95348db448f7db37a92e3bdb4814a101");
	ADD_CHECKPOINT(245000, "b856ced24e90e9243586b6cdfdd5f9295400252e746939f53c862c7e86a0dfe1");
	ADD_CHECKPOINT(247500, "2634b6cc3ebff717d795d8f28a9ba910c29471839586fe70ba356359aa32de6b");
	ADD_CHECKPOINT(250000, "306e57b36fd1d1f6d6ba2d3e44096347310c8379cdd2fa306abf347f51163814");
	ADD_CHECKPOINT(252500, "4a98b756fbe9721366d3a643593678f322188ab5f420c2ecff4d4e104f10130a");
	ADD_CHECKPOINT(255000, "f678b05ba807eae1244920c8f9648f8c2170e72dc95e6379c57665ce510bb576");
	ADD_CHECKPOINT(257500, "c0422eb9d8328deab3dca023ba82a0bb792828eb1e78ca88dbdcab39a6ab3dd0");
	ADD_CHECKPOINT(260000, "c1a114e7780e418bd84103bbd4c605a0a4bac4481e25ed7f06efeacc30c78ee9");
	ADD_CHECKPOINT(262500, "5fac5acadf52c95ddbaafee4356f892e868c94a1947219648c139646f9cbacf1");
	ADD_CHECKPOINT(265000, "851cf371ca568e3480ebff1475edb6245ec441978187d94defee4c6d855a76d3");
	ADD_CHECKPOINT(267500, "3eb4c981e36913d26899a04bd488cc39968e6164817599b2ecb172576af00c88");
	ADD_CHECKPOINT(270000, "703b6d358b9f3635ead7ac9e131e060eb5e7e3474ac97e587643959ce98f4893");
	ADD_CHECKPOINT(272500, "8f812212f015f295737169aca3c4bbb6aa8988e99a9b4a6dc0b2be0d6f2a28dc");
	ADD_CHECKPOINT(275000, "14b34b7d9065157137eb5312e069b9260b8adb8e4f516bd1869ca4686694ad61");
	ADD_CHECKPOINT(277500, "d8873dc57ce5e11a9ae5321975d2faef8e4043c154ed7e94d2889b2032eb3f89");
	ADD_CHECKPOINT(280000, "c528628acf80fd8c40e0195927f783b194c7222be048fb88b0da47143172d154");
	ADD_CHECKPOINT(282500, "b1a174fad8c36902a974828a2b6f484df8532b35e7046ab46b9fe1387d4361d2");
	ADD_CHECKPOINT(285000, "e92beb056cd2401de2eab48386abaadd8b5e2f499e5527026a3dca8c76752b78");
	ADD_CHECKPOINT(287500, "7fddbcd4a56685302bd20d608c30498538034747d7fad2cc1202fc0a7e20c529");
	ADD_CHECKPOINT(290000, "45f6fb3ff5fa3aa6ea180710907174de8317765c70d2ac5ce828e92bf11f98fb");
	ADD_CHECKPOINT(292500, "b71ba66922a17a70357f8a844496757cee4c2135648fb7976dec8ccf0a56642e");
	ADD_CHECKPOINT(295000, "3c25d3b7d646d616cbf04809939411bbfce665b5c9f9f010855e15fbc82a43c4");
	ADD_CHECKPOINT(297500, "683bc28ecdf5bf9bb273eca6824f233e68db3d16df574d9505fa32c660ab4ad5");
	ADD_CHECKPOINT(300000, "5423c839544b1a4f5b2077caadd5378877f8c786ebf1477171e00fbfe1d3124b");
	ADD_CHECKPOINT(302500, "4eb506c93378699473904eb5ea2976dc1fb48a937aefd176508c729e9ff19f8b");
	ADD_CHECKPOINT(305000, "9b7fababa769b370063f6d3f0f40f660259680e5d7a3b238719e7bf28bdbc97c");
	ADD_CHECKPOINT(307500, "1c1e922306fe6f407b42d08b64be96386fa9036df7d485d1636949875b4c8ebd");
	ADD_CHECKPOINT(310000, "0527deb1c9b5795a1d8d1dd6f3ca945936052bbd2df169f6fb5042bc746e0c52");
	ADD_CHECKPOINT(312500, "d46678203e1d28a679d2f78e871713fc89dd79c19df721ab92ead7265746ac63");
	ADD_CHECKPOINT(315000, "81b82df3b6589718b4ad323a37915870c1ce023eeff5544892758abb11b23d16");
	ADD_CHECKPOINT(317500, "206e137c40305e4b95602fe6990a93c329447faf9321978a3e2aebd3e3f0c20b");
	ADD_CHECKPOINT(320000, "1b2f2f40990d31bbcca9c76adf192ab4b0c3f0e3f35e6caf5442851e11001e65");
	ADD_CHECKPOINT(322500, "994d5d13d6a082f89d3c3102bb08f00757627b0d753bee69773855f1f45786f8");
	ADD_CHECKPOINT(325000, "a08ca93c85065b0041b8b8990acdd25363d94506e44702a48932e6c57df0aae9");
	ADD_CHECKPOINT(327500, "b62e31e240ec072ada144c1f0a95772d4b3c455fa19e15cf30957cf6eee95145");
	ADD_CHECKPOINT(330000, "3db8f8f7049a9a466ea4966f4e46028bc6cd5073bf68b5d16cf67a6add965caf");
	ADD_CHECKPOINT(332500, "0b26dba5ea24ebd20973beb979a407d7788ad554f85a1ed91fffba21dbcfd979");
	ADD_CHECKPOINT(335000, "ef8cc698bea21ed98579702b97f19b80f46f8b9e7cf45581e085149215dad9e6");
	ADD_CHECKPOINT(337500, "c12bf43f5381a2a3288bc7d0250a6d5e4ac60002d5af4379dabd24abe039565e");
	ADD_CHECKPOINT(340000, "4d06a367e31bc1b3fac87e2ff175395e6dabb0a15bc4eb42f6d57d9dd8993c4f");
	ADD_CHECKPOINT(342500, "4fd59f6db6a96e8414e43e24215ddae2e633028f99b51ac01dfee42852e4041f");
	ADD_CHECKPOINT(345000, "009c9f3eb40614cac466c33148a7aa28966a1111207ec80253896662b3908105");
	ADD_CHECKPOINT(347500, "98dc9b3995340e940cc2823b9f1269ca5701a107ccade5dd2b606ac55dbebb87");
	ADD_CHECKPOINT(350000, "9de6c6c2e095748d0bc123d77d9ef307325c1445fd07530a24319945faab4ecf");
	ADD_CHECKPOINT(352500, "453b1015b3e88beb3d4c4fa594df0291e3ad521792172f96235c1758b9689c66");
	ADD_CHECKPOINT(355000, "510f2fe16236404fba94c0d0a7c9e4a32ccdd3679a3ce53eb808aced6e29350f");
	ADD_CHECKPOINT(357500, "cf629232ae3076857d1e7328533b227158729072e81db4a0e0db72fb2d10a08e");
	ADD_CHECKPOINT(360000, "332ef3bacedb324453d90c21b7b34a4c968661c2a8a64afae47be738338daa73");
	ADD_CHECKPOINT(362500, "503d3371aaca1e83a610af031714a7a4fa2b1ee95867183296f5a776c3902b61");
	ADD_CHECKPOINT(365000, "543c1ac53be350d1bf09166da6c6539e725f2708f728cbb6ad1b1250d49e0f3c");
	ADD_CHECKPOINT(367500, "32def7a244367c58c6be87a83cddaa40afab1ec46ac0ee991a355edecdf5bf67");
	ADD_CHECKPOINT(370000, "612b2d06b414ff2aedf5e2e46bd1747ea0c423e17dd5efb25084553f05f9891a");
	ADD_CHECKPOINT(372500, "ce60047a9243c5f36b703be8dcc156ad7c9f976ef0d48505bb68e5ccdc9c7b6e");
	ADD_CHECKPOINT(375000, "af6f10143056e7ca5f62e295ad1ee0c3350a1a60d93dea5bb8c96ca141a2ebee");
	ADD_CHECKPOINT(377500, "77664e63ee4236119a40cd7acd030ace3b236456f6fa0dd93f41d502b9e52f6d");
	ADD_CHECKPOINT(380000, "959d998b4bec0053ffdb96a45fc82e5577e520a6397726a3f9900bb25bc25bb8");
	ADD_CHECKPOINT(382500, "4321808a45a3a7291c499371634df94a6dd938ffeeabf09689cfedd459c16103");
	ADD_CHECKPOINT(385000, "439f1e0628933439a505cb14c2c34a9a2861c880a2d90ed7317a92510ddc6040");
	ADD_CHECKPOINT(387500, "ace703e57bd7bc017ce72d30a2ba02ffc9a88b42a11d11fd5f02dcfb6245c60b");
	ADD_CHECKPOINT(390000, "225485978a55a67f0457223ad97ce1a233f5d9383a53d6afc675e24e9ba1fdde");
	ADD_CHECKPOINT(392500, "7ac9fc15aa5bb582461a9cea16f4c336f1d23e7f2716cb43f139e695cce9dcca");
	ADD_CHECKPOINT(395000, "5679d2ea724e9fed89d0b25b0b200571b01f253cf73f5d3ec2a38d2426599cbf");
	ADD_CHECKPOINT(397500, "13305b4122f4605f479d11ce0e4369678d62b0e559900c3f76bdccc8d9515ca2");
	ADD_CHECKPOINT(400000, "2e41bba660751a3a1a7ae7688a6831d4083940c08295fd62374978c214e35dfd");
	ADD_CHECKPOINT(402500, "bfd624cddda682d947d462b4e6cea241d48de8d4980cd2c06a7e45399be98d5e");
	ADD_CHECKPOINT(405000, "b22bf7093b7feb852d858c2cc377674dcca8fe32200fc0fb068b91ca12774230");
	ADD_CHECKPOINT(407500, "783c5e3f9fab255eaec9edcf5d0e95c81174bbb90575b33ea6dfea895a8af60c");
	ADD_CHECKPOINT(410000, "77c5cf319083452f3d8c81733c3a91a356db4aad85a13d20208c6554b39c7a99");
	ADD_CHECKPOINT(412500, "aa0e6cd43ed370bc2bc3cf1abc857fd3dd609ec97ce5acf7055cd6eeb089d3f3");
	ADD_CHECKPOINT(415000, "e5aa956076d61b3cf6d03d168346c0e9d01a4171dcc692061e981b6fe617f07f");
	ADD_CHECKPOINT(417500, "02c7a69ed465f7883e02d9805ec4e2bfed93e451601309e52d6837bc38bf72c1");
	ADD_CHECKPOINT(420000, "29b5f3857da6ed4da2e94c3d8322bf02af3672d22b9c14d9a816980eca8f2f1a");
	ADD_CHECKPOINT(422500, "c627af913456acd88099ee014b8d1db88df7faf17fd0158f416f229f14f5a51c");
	ADD_CHECKPOINT(425000, "4b015a20849d734f6ece444d4117b87ac504a0f1d32e5901bf0d4ea486c8721f");
	ADD_CHECKPOINT(427500, "1f302b72db90ef1d37ca8bd3856611eea0d17e151a928b84675c9575af541210");
	ADD_CHECKPOINT(430000, "bceebaff2480d1dd53c7db60582efd4ce8f149c308445a5a1588846dff695e0a");
	ADD_CHECKPOINT(432500, "1ed0fbd8bc065321c54baf45b9e220e5a6722af3e6fd8f6411a6bf379616a4f4");
	ADD_CHECKPOINT(435000, "a95022cd9b0fbd09a68d641c4349655b03ea590429b98bb944dbe398dfb6b281");
	ADD_CHECKPOINT(437500, "51915066e331cd4d3a73623943db3f59cca999c7fac090129e72f6c33e2b5098");
	ADD_CHECKPOINT(440000, "99395e1a863b7033a63a76b48bba8cd63c8be52334b468c8a84fa40858025450");
	ADD_CHECKPOINT(442500, "7751b5a9cd7b08aab7756c4e9a23e54dd1af08c747a9240b30199edfe279a196");
	ADD_CHECKPOINT(445000, "68bad1000efbe3af8af20179416eb50a82937b00d0ff9c27e8ef2e2f6bb9b7b4");
	ADD_CHECKPOINT(447500, "c95bc844d3a8875ce81254e54a33a706e51f4872a58c6a4512289b834bfd4810");
	ADD_CHECKPOINT(450000, "a7d8d1772104527d7b642e7210aa7d7a2c85ddeb651967885356f4edbd353b42");
	ADD_CHECKPOINT(452500, "490b2860dd98f1338590f2e673092ab910a652c98b2c1b4ecc8bcf8b8fe01430");
	ADD_CHECKPOINT(455000, "1f259255ea0fa9229ff622fe2bbb8639a906af9a013b590145f463ca901ccd90");
	ADD_CHECKPOINT(457500, "4941f38537bc348ed59616e205a1fb4b3308660d65d5e709510c91f0310dc786");
	ADD_CHECKPOINT(460000, "405d6ef8e8146ec8054cf47bb37e149b2fca0a93d274abb5091d0d6e170bd509");
	ADD_CHECKPOINT(462500, "d9689649184aac4c90679ca9413a6a17f198a9372e40f6c7386be10c02e7d5e1");

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
