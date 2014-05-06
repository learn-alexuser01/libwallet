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

namespace libwallet {

constexpr uint8_t stealth_version_byte = 0x2a;

BCW_API uint8_t stealth_address::options() const
{
    return options_;
}
BCW_API const data_chunk& stealth_address::scan_pubkey() const
{
    return scan_pubkey_;
}
BCW_API const stealth_address::pubkey_list&
    stealth_address::spend_pubkeys() const
{
    return spend_pubkeys_;
}
BCW_API size_t stealth_address::number_signatures() const
{
    return number_signatures_;
}
BCW_API const stealth_prefix& stealth_address::prefix() const
{
    return prefix_;
}

BCW_API bool stealth_address::set_encoded(const std::string& encoded_address)
{
    data_chunk raw_addr = decode_base58(encoded_address);
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
    options_ = *iter;
    ++iter;
    auto scan_key_begin = iter;
    iter += 33;
    scan_pubkey_ = data_chunk(scan_key_begin, iter);
    uint8_t number_spend_pubkeys = *iter;
    ++iter;
    estimated_data_size += number_spend_pubkeys * 33;
    BITCOIN_ASSERT(raw_addr.size() >= estimated_data_size);
    for (size_t i = 0; i < number_spend_pubkeys; ++i)
    {
        auto spend_key_begin = iter;
        iter += 33;
        spend_pubkeys_.emplace_back(data_chunk(spend_key_begin, iter));
    }
    number_signatures_ = *iter;
    ++iter;
    prefix_.number_bits = *iter;
    ++iter;
    size_t number_bitfield_bytes = 0;
    if (prefix_.number_bits > 0)
        number_bitfield_bytes = prefix_.number_bits / 8 + 1;
    estimated_data_size += number_bitfield_bytes;
    BITCOIN_ASSERT(raw_addr.size() >= estimated_data_size);
    // Unimplemented currently!
    BITCOIN_ASSERT(number_bitfield_bytes == 0);
    return true;
}

} // namespace libwallet

