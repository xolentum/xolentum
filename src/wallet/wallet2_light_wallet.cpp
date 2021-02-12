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

#include "string_tools.h"

using namespace epee;
using namespace std;
using namespace crypto;
using namespace cryptonote;

//this namespace contain shared functions from wallet2
namespace _wallet2_internal{
  bool emplace_or_replace(std::unordered_multimap<crypto::hash, tools::wallet2::pool_payment_details> &container,
    const crypto::hash &key, const tools::wallet2::pool_payment_details &pd);
}

using namespace _wallet2_internal;

namespace tools{
  void wallet2::light_wallet_get_outs(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count) {

    MDEBUG("LIGHTWALLET - Getting random outs");

    tools::COMMAND_RPC_GET_RANDOM_OUTS::request oreq;
    tools::COMMAND_RPC_GET_RANDOM_OUTS::response ores;

    size_t light_wallet_requested_outputs_count = (size_t)((fake_outputs_count + 1) * 1.5 + 1);

    // Amounts to ask for
    // MyMonero api handle amounts and fees as strings
    for(size_t idx: selected_transfers) {
      const uint64_t ask_amount = m_transfers[idx].is_rct() ? 0 : m_transfers[idx].amount();
      std::ostringstream amount_ss;
      amount_ss << ask_amount;
      oreq.amounts.push_back(amount_ss.str());
    }

    oreq.count = light_wallet_requested_outputs_count;

    {
      const boost::lock_guard<boost::recursive_mutex> lock{m_daemon_rpc_mutex};
      bool r = epee::net_utils::invoke_http_json("/get_random_outs", oreq, ores, *m_http_client, rpc_timeout, "POST");
      m_daemon_rpc_mutex.unlock();
      THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_random_outs");
      THROW_WALLET_EXCEPTION_IF(ores.amount_outs.empty() , error::wallet_internal_error, "No outputs received from light wallet node. Error: " + ores.Error);
      size_t n_outs = 0; for (const auto &e: ores.amount_outs) n_outs += e.outputs.size();
    }

    // Check if we got enough outputs for each amount
    for(auto& out: ores.amount_outs) {
      const uint64_t out_amount = boost::lexical_cast<uint64_t>(out.amount);
      THROW_WALLET_EXCEPTION_IF(out.outputs.size() < light_wallet_requested_outputs_count , error::wallet_internal_error, "Not enough outputs for amount: " + boost::lexical_cast<std::string>(out.amount));
      MDEBUG(out.outputs.size() << " outputs for amount "+ boost::lexical_cast<std::string>(out.amount) + " received from light wallet node");
    }

    MDEBUG("selected transfers size: " << selected_transfers.size());

    for(size_t idx: selected_transfers)
    {
      // Create new index
      outs.push_back(std::vector<get_outs_entry>());
      outs.back().reserve(fake_outputs_count + 1);

      // add real output first
      const transfer_details &td = m_transfers[idx];
      const uint64_t amount = td.is_rct() ? 0 : td.amount();
      outs.back().push_back(std::make_tuple(td.m_global_output_index, td.get_public_key(), rct::commit(td.amount(), td.m_mask)));
      MDEBUG("added real output " << string_tools::pod_to_hex(td.get_public_key()));

      // Even if the lightwallet server returns random outputs, we pick them randomly.
      std::vector<size_t> order;
      order.resize(light_wallet_requested_outputs_count);
      for (size_t n = 0; n < order.size(); ++n)
        order[n] = n;
      std::shuffle(order.begin(), order.end(), crypto::random_device{});


      LOG_PRINT_L2("Looking for " << (fake_outputs_count+1) << " outputs with amounts " << print_money(td.is_rct() ? 0 : td.amount()));
      MDEBUG("OUTS SIZE: " << outs.back().size());
      for (size_t o = 0; o < light_wallet_requested_outputs_count && outs.back().size() < fake_outputs_count + 1; ++o)
      {
        // Random pick
        size_t i = order[o];

        // Find which random output key to use
        bool found_amount = false;
        size_t amount_key;
        for(amount_key = 0; amount_key < ores.amount_outs.size(); ++amount_key)
        {
          if(boost::lexical_cast<uint64_t>(ores.amount_outs[amount_key].amount) == amount) {
            found_amount = true;
            break;
          }
        }
        THROW_WALLET_EXCEPTION_IF(!found_amount , error::wallet_internal_error, "Outputs for amount " + boost::lexical_cast<std::string>(ores.amount_outs[amount_key].amount) + " not found" );

        LOG_PRINT_L2("Index " << i << "/" << light_wallet_requested_outputs_count << ": idx " << ores.amount_outs[amount_key].outputs[i].global_index << " (real " << td.m_global_output_index << "), unlocked " << "(always in light)" << ", key " << ores.amount_outs[0].outputs[i].public_key);

        // Convert light wallet string data to proper data structures
        crypto::public_key tx_public_key;
        rct::key mask = AUTO_VAL_INIT(mask); // decrypted mask - not used here
        rct::key rct_commit = AUTO_VAL_INIT(rct_commit);
        THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, ores.amount_outs[amount_key].outputs[i].public_key), error::wallet_internal_error, "Invalid public_key");
        string_tools::hex_to_pod(ores.amount_outs[amount_key].outputs[i].public_key, tx_public_key);
        const uint64_t global_index = ores.amount_outs[amount_key].outputs[i].global_index;
        if(!light_wallet_parse_rct_str(ores.amount_outs[amount_key].outputs[i].rct, tx_public_key, 0, mask, rct_commit, false))
          rct_commit = rct::zeroCommit(td.amount());

        if (tx_add_fake_output(outs, global_index, tx_public_key, rct_commit, td.m_global_output_index, true)) {
          MDEBUG("added fake output " << ores.amount_outs[amount_key].outputs[i].public_key);
          MDEBUG("index " << global_index);
        }
      }

      THROW_WALLET_EXCEPTION_IF(outs.back().size() < fake_outputs_count + 1 , error::wallet_internal_error, "Not enough fake outputs found" );

      // Real output is the first. Shuffle outputs
      MTRACE(outs.back().size() << " outputs added. Sorting outputs by index:");
      std::sort(outs.back().begin(), outs.back().end(), [](const get_outs_entry &a, const get_outs_entry &b) { return std::get<0>(a) < std::get<0>(b); });

      // Print output order
      for(auto added_out: outs.back())
        MTRACE(std::get<0>(added_out));

    }
  }

  bool wallet2::light_wallet_login(bool &new_address)
  {
    MDEBUG("Light wallet login request");
    m_light_wallet_connected = false;
    tools::COMMAND_RPC_LOGIN::request request;
    tools::COMMAND_RPC_LOGIN::response response;
    request.address = get_account().get_public_address_str(m_nettype);
    request.view_key = string_tools::pod_to_hex(get_account().get_keys().m_view_secret_key);
    // Always create account if it doesn't exist.
    request.create_account = true;
    m_daemon_rpc_mutex.lock();
    bool connected = invoke_http_json("/login", request, response, rpc_timeout, "POST");
    m_daemon_rpc_mutex.unlock();
    // MyMonero doesn't send any status message. OpenMonero does.
    m_light_wallet_connected  = connected && (response.status.empty() || response.status == "success");
    new_address = response.new_address;
    MDEBUG("Status: " << response.status);
    MDEBUG("Reason: " << response.reason);
    MDEBUG("New wallet: " << response.new_address);
    if(m_light_wallet_connected)
    {
      // Clear old data on successful login.
      // m_transfers.clear();
      // m_payments.clear();
      // m_unconfirmed_payments.clear();
    }
    return m_light_wallet_connected;
  }

  bool wallet2::light_wallet_import_wallet_request(tools::COMMAND_RPC_IMPORT_WALLET_REQUEST::response &response)
  {
    MDEBUG("Light wallet import wallet request");
    tools::COMMAND_RPC_IMPORT_WALLET_REQUEST::request oreq;
    oreq.address = get_account().get_public_address_str(m_nettype);
    oreq.view_key = string_tools::pod_to_hex(get_account().get_keys().m_view_secret_key);
    m_daemon_rpc_mutex.lock();
    bool r = invoke_http_json("/import_wallet_request", oreq, response, rpc_timeout, "POST");
    m_daemon_rpc_mutex.unlock();
    THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "import_wallet_request");


    return true;
  }

  void wallet2::light_wallet_get_unspent_outs()
  {
    MDEBUG("Getting unspent outs");

    tools::COMMAND_RPC_GET_UNSPENT_OUTS::request oreq;
    tools::COMMAND_RPC_GET_UNSPENT_OUTS::response ores;

    oreq.amount = "0";
    oreq.address = get_account().get_public_address_str(m_nettype);
    oreq.view_key = string_tools::pod_to_hex(get_account().get_keys().m_view_secret_key);
    // openMonero specific
    oreq.dust_threshold = boost::lexical_cast<std::string>(::config::DEFAULT_DUST_THRESHOLD);
    // below are required by openMonero api - but are not used.
    oreq.mixin = 0;
    oreq.use_dust = true;


    m_daemon_rpc_mutex.lock();
    bool r = invoke_http_json("/get_unspent_outs", oreq, ores, rpc_timeout, "POST");
    m_daemon_rpc_mutex.unlock();
    THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_unspent_outs");
    THROW_WALLET_EXCEPTION_IF(ores.status == "error", error::wallet_internal_error, ores.reason);

    m_light_wallet_per_kb_fee = ores.per_kb_fee;

    std::unordered_map<crypto::hash,bool> transfers_txs;
    for(const auto &t: m_transfers)
      transfers_txs.emplace(t.m_txid,t.m_spent);

    MDEBUG("FOUND " << ores.outputs.size() <<" outputs");

    // return if no outputs found
    if(ores.outputs.empty())
      return;

    // Clear old outputs
    m_transfers.clear();

    for (const auto &o: ores.outputs) {
      bool spent = false;
      bool add_transfer = true;
      crypto::key_image unspent_key_image;
      crypto::public_key tx_public_key = AUTO_VAL_INIT(tx_public_key);
      THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, o.tx_pub_key), error::wallet_internal_error, "Invalid tx_pub_key field");
      string_tools::hex_to_pod(o.tx_pub_key, tx_public_key);

      for (const std::string &ski: o.spend_key_images) {
        spent = false;

        // Check if key image is ours
        THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, ski), error::wallet_internal_error, "Invalid key image");
        string_tools::hex_to_pod(ski, unspent_key_image);
        if(light_wallet_key_image_is_ours(unspent_key_image, tx_public_key, o.index)){
          MTRACE("Output " << o.public_key << " is spent. Key image: " <<  ski);
          spent = true;
          break;
        } {
          MTRACE("Unspent output found. " << o.public_key);
        }
      }

      // Check if tx already exists in m_transfers.
      crypto::hash txid;
      crypto::public_key tx_pub_key;
      crypto::public_key public_key;
      THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, o.tx_hash), error::wallet_internal_error, "Invalid tx_hash field");
      THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, o.public_key), error::wallet_internal_error, "Invalid public_key field");
      THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, o.tx_pub_key), error::wallet_internal_error, "Invalid tx_pub_key field");
      string_tools::hex_to_pod(o.tx_hash, txid);
      string_tools::hex_to_pod(o.public_key, public_key);
      string_tools::hex_to_pod(o.tx_pub_key, tx_pub_key);

      for(auto &t: m_transfers){
        if(t.get_public_key() == public_key) {
          t.m_spent = spent;
          add_transfer = false;
          break;
        }
      }

      if(!add_transfer)
        continue;

      m_transfers.push_back(transfer_details{});
      transfer_details& td = m_transfers.back();

      td.m_block_height = o.height;
      td.m_global_output_index = o.global_index;
      td.m_txid = txid;

      // Add to extra
      add_tx_pub_key_to_extra(td.m_tx, tx_pub_key);

      td.m_key_image = unspent_key_image;
      td.m_key_image_known = !m_watch_only && !m_multisig;
      td.m_key_image_request = false;
      td.m_key_image_partial = m_multisig;
      td.m_amount = o.amount;
      td.m_pk_index = 0;
      td.m_internal_output_index = o.index;
      td.m_spent = spent;
      td.m_frozen = false;

      tx_out txout;
      txout.target = txout_to_key(public_key);
      txout.amount = td.m_amount;

      td.m_tx.vout.resize(td.m_internal_output_index + 1);
      td.m_tx.vout[td.m_internal_output_index] = txout;

      // Add unlock time and coinbase bool got from get_address_txs api call
      std::unordered_map<crypto::hash,address_tx>::const_iterator found = m_light_wallet_address_txs.find(txid);
      THROW_WALLET_EXCEPTION_IF(found == m_light_wallet_address_txs.end(), error::wallet_internal_error, "Lightwallet: tx not found in m_light_wallet_address_txs");
      bool miner_tx = found->second.m_coinbase;
      td.m_tx.unlock_time = found->second.m_unlock_time;

      if (!o.rct.empty())
      {
        // Coinbase tx's
        if(miner_tx)
        {
          td.m_mask = rct::identity();
        }
        else
        {
          // rct txs
          // decrypt rct mask, calculate commit hash and compare against blockchain commit hash
          rct::key rct_commit;
          light_wallet_parse_rct_str(o.rct, tx_pub_key, td.m_internal_output_index, td.m_mask, rct_commit, true);
          bool valid_commit = (rct_commit == rct::commit(td.amount(), td.m_mask));
          if(!valid_commit)
          {
            MDEBUG("output index: " << o.global_index);
            MDEBUG("mask: " + string_tools::pod_to_hex(td.m_mask));
            MDEBUG("calculated commit: " + string_tools::pod_to_hex(rct::commit(td.amount(), td.m_mask)));
            MDEBUG("expected commit: " + string_tools::pod_to_hex(rct_commit));
            MDEBUG("amount: " << td.amount());
          }
          THROW_WALLET_EXCEPTION_IF(!valid_commit, error::wallet_internal_error, "Lightwallet: rct commit hash mismatch!");
        }
        td.m_rct = true;
      }
      else
      {
        td.m_mask = rct::identity();
        td.m_rct = false;
      }
      if(!spent)
        set_unspent(m_transfers.size()-1);
      m_key_images[td.m_key_image] = m_transfers.size()-1;
      m_pub_keys[td.get_public_key()] = m_transfers.size()-1;
    }
  }

  bool wallet2::light_wallet_get_address_info(tools::COMMAND_RPC_GET_ADDRESS_INFO::response &response)
  {
    MTRACE(__FUNCTION__);

    tools::COMMAND_RPC_GET_ADDRESS_INFO::request request;

    request.address = get_account().get_public_address_str(m_nettype);
    request.view_key = string_tools::pod_to_hex(get_account().get_keys().m_view_secret_key);
    m_daemon_rpc_mutex.lock();
    bool r = invoke_http_json("/get_address_info", request, response, rpc_timeout, "POST");
    m_daemon_rpc_mutex.unlock();
    THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_address_info");
    // TODO: Validate result
    return true;
  }

  void wallet2::light_wallet_get_address_txs()
  {
    MDEBUG("Refreshing light wallet");

    tools::COMMAND_RPC_GET_ADDRESS_TXS::request ireq;
    tools::COMMAND_RPC_GET_ADDRESS_TXS::response ires;

    ireq.address = get_account().get_public_address_str(m_nettype);
    ireq.view_key = string_tools::pod_to_hex(get_account().get_keys().m_view_secret_key);
    m_daemon_rpc_mutex.lock();
    bool r = invoke_http_json("/get_address_txs", ireq, ires, rpc_timeout, "POST");
    m_daemon_rpc_mutex.unlock();
    THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_address_txs");
    //OpenMonero sends status=success, Mymonero doesn't.
    THROW_WALLET_EXCEPTION_IF((!ires.status.empty() && ires.status != "success"), error::no_connection_to_daemon, "get_address_txs");


    // Abort if no transactions
    if(ires.transactions.empty())
      return;

    // Create searchable vectors
    std::vector<crypto::hash> payments_txs;
    for(const auto &p: m_payments)
      payments_txs.push_back(p.second.m_tx_hash);
    std::vector<crypto::hash> unconfirmed_payments_txs;
    for(const auto &up: m_unconfirmed_payments)
      unconfirmed_payments_txs.push_back(up.second.m_pd.m_tx_hash);

    // for balance calculation
    uint64_t wallet_total_sent = 0;
    // txs in pool
    std::vector<crypto::hash> pool_txs;

    for (const auto &t: ires.transactions) {
      const uint64_t total_received = t.total_received;
      uint64_t total_sent = t.total_sent;

      // Check key images - subtract fake outputs from total_sent
      for(const auto &so: t.spent_outputs)
      {
        crypto::public_key tx_public_key;
        crypto::key_image key_image;
        THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, so.tx_pub_key), error::wallet_internal_error, "Invalid tx_pub_key field");
        THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, so.key_image), error::wallet_internal_error, "Invalid key_image field");
        string_tools::hex_to_pod(so.tx_pub_key, tx_public_key);
        string_tools::hex_to_pod(so.key_image, key_image);

        if(!light_wallet_key_image_is_ours(key_image, tx_public_key, so.out_index)) {
          THROW_WALLET_EXCEPTION_IF(so.amount > t.total_sent, error::wallet_internal_error, "Lightwallet: total sent is negative!");
          total_sent -= so.amount;
        }
      }

      // Do not add tx if empty.
      if(total_sent == 0 && total_received == 0)
        continue;

      crypto::hash payment_id = null_hash;
      crypto::hash tx_hash;

      THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, t.payment_id), error::wallet_internal_error, "Invalid payment_id field");
      THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, t.hash), error::wallet_internal_error, "Invalid hash field");
      string_tools::hex_to_pod(t.payment_id, payment_id);
      string_tools::hex_to_pod(t.hash, tx_hash);

      // lightwallet specific info
      bool incoming = (total_received > total_sent);
      address_tx address_tx;
      address_tx.m_tx_hash = tx_hash;
      address_tx.m_incoming = incoming;
      address_tx.m_amount  =  incoming ? total_received - total_sent : total_sent - total_received;
      address_tx.m_fee = 0;                 // TODO
      address_tx.m_block_height = t.height;
      address_tx.m_unlock_time  = t.unlock_time;
      address_tx.m_timestamp = t.timestamp;
      address_tx.m_coinbase  = t.coinbase;
      address_tx.m_mempool  = t.mempool;
      m_light_wallet_address_txs.emplace(tx_hash,address_tx);

      // populate data needed for history (m_payments, m_unconfirmed_payments, m_confirmed_txs)
      // INCOMING transfers
      if(total_received > total_sent) {
        payment_details payment;
        payment.m_tx_hash = tx_hash;
        payment.m_amount       = total_received - total_sent;
        payment.m_fee          = 0;         // TODO
        payment.m_block_height = t.height;
        payment.m_unlock_time  = t.unlock_time;
        payment.m_timestamp = t.timestamp;
        payment.m_coinbase = t.coinbase;

        if (t.mempool) {
          if (std::find(unconfirmed_payments_txs.begin(), unconfirmed_payments_txs.end(), tx_hash) == unconfirmed_payments_txs.end()) {
            pool_txs.push_back(tx_hash);
            // assume false as we don't get that info from the light wallet server
            crypto::hash payment_id;
            THROW_WALLET_EXCEPTION_IF(!epee::string_tools::hex_to_pod(t.payment_id, payment_id),
                error::wallet_internal_error, "Failed to parse payment id");
            emplace_or_replace(m_unconfirmed_payments, payment_id, pool_payment_details{payment, false});
            if (0 != m_callback) {
              m_callback->on_lw_unconfirmed_money_received(t.height, payment.m_tx_hash, payment.m_amount);
            }
          }
        } else {
          if (std::find(payments_txs.begin(), payments_txs.end(), tx_hash) == payments_txs.end()) {
            m_payments.emplace(tx_hash, payment);
            if (0 != m_callback) {
              m_callback->on_lw_money_received(t.height, payment.m_tx_hash, payment.m_amount);
            }
          }
        }
      // Outgoing transfers
      } else {
        uint64_t amount_sent = total_sent - total_received;
        cryptonote::transaction dummy_tx; // not used by light wallet
        // increase wallet total sent
        wallet_total_sent += total_sent;
        if (t.mempool)
        {
          // Handled by add_unconfirmed_tx in commit_tx
          // If sent from another wallet instance we need to add it
          if(m_unconfirmed_txs.find(tx_hash) == m_unconfirmed_txs.end())
          {
            unconfirmed_transfer_details utd;
            utd.m_amount_in = amount_sent;
            utd.m_amount_out = amount_sent;
            utd.m_change = 0;
            utd.m_payment_id = payment_id;
            utd.m_timestamp = t.timestamp;
            utd.m_state = wallet2::unconfirmed_transfer_details::pending;
            m_unconfirmed_txs.emplace(tx_hash,utd);
          }
        }
        else
        {
          // Only add if new
          auto confirmed_tx = m_confirmed_txs.find(tx_hash);
          if(confirmed_tx == m_confirmed_txs.end()) {
            // tx is added to m_unconfirmed_txs - move to confirmed
            if(m_unconfirmed_txs.find(tx_hash) != m_unconfirmed_txs.end())
            {
              process_unconfirmed(tx_hash, dummy_tx, t.height);
            }
            // Tx sent by another wallet instance
            else
            {
              confirmed_transfer_details ctd;
              ctd.m_amount_in = amount_sent;
              ctd.m_amount_out = amount_sent;
              ctd.m_change = 0;
              ctd.m_payment_id = payment_id;
              ctd.m_block_height = t.height;
              ctd.m_timestamp = t.timestamp;
              m_confirmed_txs.emplace(tx_hash,ctd);
            }
            if (0 != m_callback)
            {
              m_callback->on_lw_money_spent(t.height, tx_hash, amount_sent);
            }
          }
          // If not new - check the amount and update if necessary.
          // when sending a tx to same wallet the receiving amount has to be credited
          else
          {
            if(confirmed_tx->second.m_amount_in != amount_sent || confirmed_tx->second.m_amount_out != amount_sent)
            {
              MDEBUG("Adjusting amount sent/received for tx: <" + t.hash + ">. Is tx sent to own wallet? " << print_money(amount_sent) << " != " << print_money(confirmed_tx->second.m_amount_in));
              confirmed_tx->second.m_amount_in = amount_sent;
              confirmed_tx->second.m_amount_out = amount_sent;
              confirmed_tx->second.m_change = 0;
            }
          }
        }
      }
    }
    // TODO: purge old unconfirmed_txs
    remove_obsolete_pool_txs(pool_txs);

    // Calculate wallet balance
    m_light_wallet_balance = ires.total_received-wallet_total_sent;
    // MyMonero doesn't send unlocked balance
    if(ires.total_received_unlocked > 0)
      m_light_wallet_unlocked_balance = ires.total_received_unlocked-wallet_total_sent;
    else
      m_light_wallet_unlocked_balance = m_light_wallet_balance;
  }

  bool wallet2::light_wallet_parse_rct_str(const std::string& rct_string, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key& decrypted_mask, rct::key& rct_commit, bool decrypt) const
  {
    // rct string is empty if output is non RCT
    if (rct_string.empty())
      return false;
    // rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
    rct::key encrypted_mask;
    std::string rct_commit_str = rct_string.substr(0,64);
    std::string encrypted_mask_str = rct_string.substr(64,64);
    THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, rct_commit_str), error::wallet_internal_error, "Invalid rct commit hash: " + rct_commit_str);
    THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, encrypted_mask_str), error::wallet_internal_error, "Invalid rct mask: " + encrypted_mask_str);
    string_tools::hex_to_pod(rct_commit_str, rct_commit);
    string_tools::hex_to_pod(encrypted_mask_str, encrypted_mask);
    if (decrypt) {
      // Decrypt the mask
      crypto::key_derivation derivation;
      bool r = generate_key_derivation(tx_pub_key, get_account().get_keys().m_view_secret_key, derivation);
      THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
      crypto::secret_key scalar;
      crypto::derivation_to_scalar(derivation, internal_output_index, scalar);
      sc_sub(decrypted_mask.bytes,encrypted_mask.bytes,rct::hash_to_scalar(rct::sk2rct(scalar)).bytes);
    }
    return true;
  }

  bool wallet2::light_wallet_key_image_is_ours(const crypto::key_image& key_image, const crypto::public_key& tx_public_key, uint64_t out_index)
  {
    // Lookup key image from cache
    serializable_map<uint64_t, crypto::key_image> index_keyimage_map;
    serializable_unordered_map<crypto::public_key, serializable_map<uint64_t, crypto::key_image> >::const_iterator found_pub_key = m_key_image_cache.find(tx_public_key);
    if(found_pub_key != m_key_image_cache.end()) {
      // pub key found. key image for index cached?
      index_keyimage_map = found_pub_key->second;
      std::map<uint64_t,crypto::key_image>::const_iterator index_found = index_keyimage_map.find(out_index);
      if(index_found != index_keyimage_map.end())
        return key_image == index_found->second;
    }

    // Not in cache - calculate key image
    crypto::key_image calculated_key_image;
    cryptonote::keypair in_ephemeral;

    // Subaddresses aren't supported in mymonero/openmonero yet. Roll out the original scheme:
    //   compute D = a*R
    //   compute P = Hs(D || i)*G + B
    //   compute x = Hs(D || i) + b      (and check if P==x*G)
    //   compute I = x*Hp(P)
    const account_keys& ack = get_account().get_keys();
    crypto::key_derivation derivation;
    bool r = crypto::generate_key_derivation(tx_public_key, ack.m_view_secret_key, derivation);
    CHECK_AND_ASSERT_MES(r, false, "failed to generate_key_derivation(" << tx_public_key << ", " << ack.m_view_secret_key << ")");

    r = crypto::derive_public_key(derivation, out_index, ack.m_account_address.m_spend_public_key, in_ephemeral.pub);
    CHECK_AND_ASSERT_MES(r, false, "failed to derive_public_key (" << derivation << ", " << out_index << ", " << ack.m_account_address.m_spend_public_key << ")");

    crypto::derive_secret_key(derivation, out_index, ack.m_spend_secret_key, in_ephemeral.sec);
    crypto::public_key out_pkey_test;
    r = crypto::secret_key_to_public_key(in_ephemeral.sec, out_pkey_test);
    CHECK_AND_ASSERT_MES(r, false, "failed to secret_key_to_public_key(" << in_ephemeral.sec << ")");
    CHECK_AND_ASSERT_MES(in_ephemeral.pub == out_pkey_test, false, "derived secret key doesn't match derived public key");

    crypto::generate_key_image(in_ephemeral.pub, in_ephemeral.sec, calculated_key_image);

    index_keyimage_map.emplace(out_index, calculated_key_image);
    m_key_image_cache.emplace(tx_public_key, index_keyimage_map);
    return key_image == calculated_key_image;
  }

}
