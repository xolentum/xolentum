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
#pragma once
#include <boost/logic/tribool_fwd.hpp>
#include <atomic>
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/difficulty.h"
#include "math_helper.h"
#ifdef _WIN32
#include <windows.h>
#endif

namespace cryptonote{
    class tx_pow_miner{
    public:
      tx_pow_miner();
      tx_pow_miner(const uint32_t n_threads);
      ~tx_pow_miner();
      /**
      *@brief start tx pow mining
      *
      *@param transaction itself
      */
      void mine(cryptonote::transaction& tx,difficulty_type difficulty);
      /*
      *@brief set number of mining threads
      */
      void set_total_threads(const uint32_t n_threads);
    private:
      void stop_signal();
      void worker();
      //used by thread to submit correct hash
      epee::critical_section m_state_lock;
      uint32_t m_starter_nonce;
      boost::thread::attributes m_attrs;
      difficulty_type m_diffic;
      volatile uint32_t m_stop;
      //used by threads on index management and counter
      epee::critical_section m_threads_lock;
      std::list<boost::thread> m_threads;
      volatile uint32_t m_thread_index;
      volatile uint32_t m_threads_active;
      cryptonote::transaction m_tx;
      volatile uint32_t m_threads_total;
    };
}
