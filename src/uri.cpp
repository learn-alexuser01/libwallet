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
#include <wallet/uri.hpp>

#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <bitcoin/constants.hpp>
#include <bitcoin/utility/base58.hpp>

namespace libwallet {

static bool is_digit(char c)
{
    return '0' <= c && c <= '9';
}
static bool is_hex(char c)
{
    return is_digit(c) || ('A' <= c && c <= 'F') || ('a' <= c && c <= 'f');
}
static bool is_qchar(char c)
{
    return
        ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || is_digit(c) ||
        '-' == c || '.' == c || '_' == c || '~' == c || // unreserved
        '!' == c || '$' == c || '\'' == c || '(' == c || ')' == c ||
        '*' == c || '+' == c || ',' == c || ';' == c || // sub-delims
        ':' == c || '@' == c || // pchar
        '/' == c || '?' == c;   // query
}
static bool isnt_amp(char c)
{
    return '&' != c;
}

static unsigned from_hex(char c)
{
    return
        'A' <= c && c <= 'F' ? 10 + c - 'A' :
        'a' <= c && c <= 'f' ? 10 + c - 'a' :
        c - '0';
}

/**
 * Unescapes a percent-encoded string while advancing the iterator.
 * @param i set to one-past the last-read character on return.
 */
typedef std::string::const_iterator sci;
static std::string unescape(sci& i, sci end, bool (*is_valid)(char))
{
    auto j = i;
    size_t count = 0;
    while (end != i && (is_valid(*i) ||
        ('%' == *i && 2 < end - i && is_hex(i[1]) && is_hex(i[2]))))
    {
        ++count;
        i += ('%' == *i ? 3 : 1);
    }
    std::string out;
    out.reserve(count);
    while (j != i)
    {
        out.push_back('%' == *j ? from_hex(j[1]) << 4 | from_hex(j[2]) : *j);
        j += ('%' == *j ? 3 : 1);
    }
    return out;
}

/**
 * Parses a URI string into its individual components.
 * @param strict Only accept properly-escaped parameters. Some bitcoin
 * software does not properly escape URI parameters, and setting strict to
 * false allows these malformed URI's to parse anyhow.
 * @return false if the URI is malformed.
 */
bool uri_parse(const std::string& uri, uri_visitor& result, bool strict)
{
    auto i = uri.begin();

    // URI scheme (this approach does not depend on the current locale):
    const char* lower = "bitcoin:";
    const char* upper = "BITCOIN:";
    while (*lower)
    {
        if (uri.end() == i || (*lower != *i && *upper != *i))
            return false;
        ++lower; ++upper; ++i;
    }

    // Payment address:
    std::string address = unescape(i, uri.end(), libbitcoin::is_base58);
    if (uri.end() != i && '?' != *i)
        return false;
    if (!address.empty() && !result.got_address(address))
        return false;

    // Parameters:
    while (uri.end() != i)
    {
        ++i; // Consume '?' or '&'
        std::string key = unescape(i, uri.end(), is_qchar);
        std::string value;
        if (uri.end() != i && '=' == *i)
        {
            ++i; // Consume '='
            if (key.empty())
                return false;
            value = unescape(i, uri.end(), strict ? is_qchar : isnt_amp);
        }
        if (uri.end() != i && '&' != *i)
            return false;
        if (!key.empty() && !result.got_param(key, value))
            return false;
    }
    return true;
}

bool uri_parse_result::got_address(std::string& address)
{
    libbitcoin::payment_address payaddr;
    if (!payaddr.set_encoded(address))
        return false;
    this->address.reset(payaddr);
    return true;
}

bool uri_parse_result::got_param(std::string& key, std::string& value)
{
    if (key == "amount")
    {
        uint64_t amount = parse_amount(value);
        if (std::numeric_limits<uint64_t>::max() == amount)
            return false;
        this->amount.reset(amount);
    }
    else if (key == "label")
        label.reset(value);
    else if (key == "message")
        message.reset(value);
    else if (key == "r")
        r.reset(value);
    else if (!key.compare(0, 4, "req-"))
        return false;
    return true;
}

uint64_t parse_amount(const std::string& amount)
{
    // Split string at .
    std::vector<std::string> segments;
    boost::split(segments, amount, boost::is_any_of("."));
    // Return false if not 1 or 2 parts.
    if (segments.empty() || segments.size() > 2)
        return invalid_amount;
    // Integer and decimal part.
    std::string integer_part = std::move(segments[0]);
    std::string decimal_part = "0";
    if (segments.size() == 2)
        decimal_part = std::move(segments[1]);
    // Handle cases where integer or decimal parts are empty strings.
    if (integer_part.empty())
        integer_part = "0";
    if (decimal_part.empty())
        decimal_part = "0";
    // Trim 2nd value to maximum of 8 chars.
    if (decimal_part.size() > 8)
        decimal_part.resize(8);
    uint64_t integer = 0, decimal = 0;
    try
    {
        integer = boost::lexical_cast<uint64_t>(integer_part);
        decimal = boost::lexical_cast<uint64_t>(decimal_part);
    }
    catch (boost::bad_lexical_cast)
    {
        return invalid_amount;
    }
    // Add number of neccessary 0s to the decimal part.
    decimal *= std::pow(10, 8 - decimal_part.size());
    return libbitcoin::coin_price(integer) + decimal;
}

} // namespace libwallet
