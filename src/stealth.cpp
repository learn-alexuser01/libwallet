/**
 * Copyright (c) 2011-2013 libwallet developers (see AUTHORS)
 *
 * This file is part of libwallet.
 *
 * libwallet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include <wallet/stealth.hpp>

#include <bitcoin/utility/assert.hpp>
#include <bitcoin/utility/base58.hpp>
#include <bitcoin/utility/checksum.hpp>
#include <bitcoin/utility/hash.hpp>

namespace libwallet {

constexpr uint8_t stealth_version_byte = 0x2a;

BCW_API bool stealth_address::set_encoded(const std::string& encoded_address)
{
    ec_point raw_addr = decode_base58(encoded_address);
    if (!verify_checksum(raw_addr))
        return false;
    BITCOIN_ASSERT(raw_addr.size() >= 4);
    auto checksum_begin = raw_addr.end() - 4;
    // Delete checksum bytes.
    raw_addr.erase(checksum_begin, raw_addr.end());
    // https://wiki.unsystem.net/index.php/DarkWallet/Stealth#Address_format
    // [version] [options] [scan_key] [N] ... [Nsigs] [prefix_length] ...
    size_t estimated_data_size = 1 + 1 + 33 + 1 + 1 + 1;
    BITCOIN_ASSERT(raw_addr.size() >= estimated_data_size);
    auto iter = raw_addr.begin();
    uint8_t version = *iter;
    if (version != stealth_version_byte)
        return false;
    ++iter;
    options = *iter;
    ++iter;
    auto scan_key_begin = iter;
    iter += 33;
    scan_pubkey = ec_point(scan_key_begin, iter);
    uint8_t number_spend_pubkeys = *iter;
    ++iter;
    estimated_data_size += number_spend_pubkeys * 33;
    BITCOIN_ASSERT(raw_addr.size() >= estimated_data_size);
    for (size_t i = 0; i < number_spend_pubkeys; ++i)
    {
        auto spend_key_begin = iter;
        iter += 33;
        spend_pubkeys.emplace_back(ec_point(spend_key_begin, iter));
    }
    number_signatures = *iter;
    ++iter;
    prefix.number_bits = *iter;
    ++iter;
    size_t number_bitfield_bytes = 0;
    if (prefix.number_bits > 0)
        number_bitfield_bytes = prefix.number_bits / 8 + 1;
    estimated_data_size += number_bitfield_bytes;
    BITCOIN_ASSERT(raw_addr.size() >= estimated_data_size);
    // Unimplemented currently!
    BITCOIN_ASSERT(number_bitfield_bytes == 0);
    return true;
}

ec_secret shared_secret(const ec_secret& secret, ec_point point)
{
    bool success = point *= secret;
    BITCOIN_ASSERT(success);
    return sha256_hash(point);
}

BCW_API ec_point initiate_stealth(
    const ec_secret& ephem_secret, const ec_point& scan_pubkey,
    const ec_point& spend_pubkey)
{
    ec_point final = spend_pubkey;
    bool success = final += shared_secret(ephem_secret, scan_pubkey);
    BITCOIN_ASSERT(success);
    return final;
}

BCW_API ec_point uncover_stealth(
    const ec_point& ephem_pubkey, const ec_secret& scan_secret,
    const ec_point& spend_pubkey)
{
    ec_point final = spend_pubkey;
    bool success = final += shared_secret(scan_secret, ephem_pubkey);
    BITCOIN_ASSERT(success);
    return final;
}

BCW_API ec_secret uncover_stealth_secret(
    const ec_point& ephem_pubkey, const ec_secret& scan_secret,
    const ec_secret& spend_secret)
{
    ec_secret final = spend_secret;
    bool success = final += shared_secret(scan_secret, ephem_pubkey);
    BITCOIN_ASSERT(success);
    return final;
}

} // namespace libwallet

