/*
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
#include <wallet/key_formats.hpp>

#include <bitcoin/bitcoin.hpp>

namespace libwallet {

std::string secret_to_wif(const secret_parameter& secret, bool compressed)
{
    data_chunk data;
    data.reserve(1 + hash_size + 1 + 4);

    data.push_back(payment_address::wif_version);
    extend_data(data, secret);
    if (compressed)
        data.push_back(0x01);

    append_checksum(data);
    return encode_base58(data);
}

secret_parameter wif_to_secret(const std::string& wif)
{
    if (!is_base58(wif))
        return secret_parameter();
    data_chunk decoded = decode_base58(wif);
    // 1 marker, 32 byte secret, optional 1 compressed flag, 4 checksum bytes
    if (decoded.size() != 1 + hash_size + 4 &&
        decoded.size() != 1 + hash_size + 1 + 4)
        return secret_parameter();
    if (!verify_checksum(decoded))
        return secret_parameter();
    // Check first byte is valid
    if (decoded[0] != payment_address::wif_version)
        return secret_parameter();

    // Checks passed. Drop the 0x80 start byte and checksum.
    decoded.erase(decoded.begin());
    decoded.erase(decoded.end() - 4, decoded.end());
    // If length is still 33 and last byte is 0x01, drop it.
    if (decoded.size() == 33 && decoded[32] == (uint8_t)0x01)
        decoded.erase(decoded.begin()+32);
    secret_parameter secret;
    BITCOIN_ASSERT(secret.size() == decoded.size());
    std::copy(decoded.begin(), decoded.end(), secret.begin());
    return secret;
}

bool is_wif_compressed(const std::string& wif) {
    data_chunk decoded = decode_base58(wif);
    return decoded.size() == (1 + hash_size + 1 + 4) &&
        decoded[33] == (uint8_t)0x01;
}

hash_digest single_sha256(const std::string& mini)
{
    data_chunk chunk = data_chunk(mini.begin(), mini.end());
    return sha256_hash(chunk);
}

bool check_minikey(const std::string& minikey)
{
    // Legacy minikeys are 22 chars long
    if (minikey.size() != 22 && minikey.size() != 30)
        return false;
    return single_sha256(minikey + "?")[0] == 0x00;
}

secret_parameter minikey_to_secret(const std::string& minikey)
{
    return check_minikey(minikey) ? single_sha256(minikey) :
        secret_parameter();
}

} // libwallet

