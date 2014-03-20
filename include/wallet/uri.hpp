/*
 * Copyright (c) 2011-2013 libwallet developers (see AUTHORS)
 *
 * This file is part of libwallet.
 *
 * libwallet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBWALLET_URI_HPP
#define LIBWALLET_URI_HPP

#include <bitcoin/address.hpp>

namespace libwallet {

struct uri_parse_handler {
    virtual void got_address(std::string& address) = 0;
    virtual void got_param(std::string& key, std::string& value) = 0;
};

bool uri_parse(const std::string& uri, uri_parse_handler& handler,
    bool strict=true);
bool uri_validate(const std::string& uri, bool strict=true);

/**
 * A decoded bitcoin URI corresponding to BIP 21 and BIP 72.
 * All string members are UTF-8.
 */
struct decoded_uri
{
    bool valid;
    bool has_address;
    bool has_amount;
    bool has_label;
    bool has_message;
    bool has_r;

    libbitcoin::payment_address address;
    uint64_t amount;
    std::string label;
    std::string message;
    std::string r;

    decoded_uri()
      : valid(true), has_address(false), has_amount(false),
        has_label(false), has_message(false), has_r(false)
    {}
};

decoded_uri uri_decode(const std::string& uri, bool strict=true);

constexpr uint64_t invalid_amount = std::numeric_limits<uint64_t>::max();

/**
 * Parses a bitcoin amount string.
 * @return string value, in satoshis, or -1 for failure.
 */
uint64_t parse_amount(const std::string& amount);

} // libwallet

#endif

