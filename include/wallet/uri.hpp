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

#include <sstream>
#include <boost/optional.hpp>
#include <bitcoin/define.hpp>
#include <bitcoin/address.hpp>

namespace libwallet {

class BC_API uri_visitor
{
public:
    virtual bool got_address(std::string& address) = 0;
    virtual bool got_param(std::string& key, std::string& value) = 0;
};

/**
 * A decoded bitcoin URI corresponding to BIP 21 and BIP 72.
 * All string members are UTF-8.
 */
class BC_API uri_parse_result
  : public uri_visitor
{
public:
    typedef boost::optional<libbitcoin::payment_address> optional_address;
    typedef boost::optional<uint64_t> optional_amount;
    typedef boost::optional<std::string> optional_string;

    optional_address address;
    optional_amount amount;
    optional_string label;
    optional_string message;
    optional_string r;

    bool got_address(std::string& address);
    bool got_param(std::string& key, std::string& value);
};

BC_API bool uri_parse(const std::string& uri,
    uri_visitor& result, bool strict=true);

#ifdef _WIN32
constexpr uint64_t invalid_amount = UINT_LEAST64_MAX;
#else
constexpr uint64_t invalid_amount = std::numeric_limits<uint64_t>::max();
#endif

/**
 * Validates and parses an amount string according to the BIP 21 grammar.
 * @param decmial_place the location of the decimal point. The default
 * value converts bitcoins to satoshis.
 * @return parsed value, or invalid_amount for failure.
 */
BC_API uint64_t parse_amount(const std::string& amount,
    unsigned decimal_place=8);

/**
 * Assembles a bitcoin URI string.
 */
class uri_writer
{
public:
    BC_API uri_writer();

    // Formatted:
    BC_API void write_address(const libbitcoin::payment_address& address);
    BC_API void write_amount(uint64_t satoshis);
    BC_API void write_label(const std::string& label);
    BC_API void write_message(const std::string& message);
    BC_API void write_r(const std::string& r);

    // Raw:
    BC_API void write_address(const std::string& address);
    BC_API void write_param(const std::string& key, const std::string& value);

    BC_API std::string string() const;

private:
    std::ostringstream stream_;
    bool first_param_;
};

} // libwallet

#endif

