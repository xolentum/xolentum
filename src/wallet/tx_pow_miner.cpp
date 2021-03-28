// Copyright (c) 2020-2021, The Xolentum Project
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
#include "wallet/tx_pow_miner.h"
#include <boost/interprocess/detail/atomic.hpp>
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "misc_language.h"
#include "include_base_utils.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "txminer"

namespace cryptonote{
  //Delegating constructor
  tx_pow_miner::tx_pow_miner():tx_pow_miner(boost::thread::hardware_concurrency())
  {
  }
  tx_pow_miner::tx_pow_miner(const uint32_t n_threads):m_stop(0),
  m_threads_active(0),
  m_thread_index(0),
  m_threads_total(n_threads){
    m_attrs.set_stack_size(THREAD_STACK_SIZE);
  }
  tx_pow_miner::~tx_pow_miner(){
  }
  void tx_pow_miner::mine(cryptonote::transaction& tx,difficulty_type difficulty){
    if(m_threads_active)
      throw std::runtime_error("Invalid operation: attempting to start miner while it is already started");
    //copy the data into the instance
    m_diffic=difficulty;
    m_tx=tx;
    m_thread_index=0;
    //generate random for the starting nonce
    m_starter_nonce = crypto::rand<uint32_t>();
    CRITICAL_REGION_LOCAL(m_threads_lock);//we are going to modify the threads structures, lock it down
    boost::interprocess::ipcdetail::atomic_write32(&m_stop, 0);
    boost::interprocess::ipcdetail::atomic_write32(&m_thread_index, 0);
    MGINFO("Starting miner for difficulty "<<difficulty);
    for(size_t i = 0; i != m_threads_total; i++)
    {
      m_threads.push_back(boost::thread(m_attrs, boost::bind(&tx_pow_miner::worker, this)));
    }
    //wait all threads done
    while(!m_threads.empty()){
      m_threads.back().join();
      m_threads.pop_back();
    }
    tx.nonce=m_starter_nonce;
    tx.invalidate_hashes();
    MGINFO("Miner done for difficulty "<<difficulty);
  }
  void tx_pow_miner::worker(){
    uint32_t th_local_index = boost::interprocess::ipcdetail::atomic_inc32(&m_thread_index);
    uint32_t nonce = m_starter_nonce + th_local_index;
    cryptonote::transaction tx=m_tx;
    crypto::hash hash;
    boost::interprocess::ipcdetail::atomic_inc32(&m_threads_active);
    MGINFO("Tx Miner Thread Started id="<<th_local_index);
    while(!m_stop)
    {
      tx.nonce=nonce;
      //clear hash to 0xFF so in case the hash function fails to PoW verification
      //will also fail
      memset(hash.data, 0xff, sizeof(hash.data));
      calculate_transaction_hash_pow(tx,hash);
      if(check_hash(hash,m_diffic)){
        stop_signal();//stop the miner
        //we need to publish this value
        CRITICAL_REGION_BEGIN(m_state_lock);
        //set the value
        m_starter_nonce=nonce;
        CRITICAL_REGION_END();
        //explicitly break out
        break;
      }
      nonce+=th_local_index+1;
    }
    boost::interprocess::ipcdetail::atomic_dec32(&m_threads_active);
    MGINFO("Tx Miner Thread Ended id="<<th_local_index);
  }
  void tx_pow_miner::stop_signal(){
    boost::interprocess::ipcdetail::atomic_write32(&m_stop, 1);
  }
  void tx_pow_miner::set_total_threads(const uint32_t n_threads){
    if(m_threads_active)
      throw std::runtime_error("Invalid operation: attempting to set total mining threads while it is already started");
    m_threads_total=n_threads;
  }
}
