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

#include <bitcoin/utility/base58.hpp>
#include <algorithm>
#include <stdlib.h>

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
static bool is_qchar_or_space(char c)
{
    return is_qchar(c) || ' ' == c;
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

bool uri_parse(const std::string& uri, uri_parse_handler& handler)
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
    if (!address.empty())
        handler.got_address(address);

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
            value = unescape(i, uri.end(), is_qchar_or_space);
        }
        if (uri.end() != i && '&' != *i)
            return false;
        if (!key.empty())
            handler.got_param(key, value);
    }
    return true;
}

bool uri_validate(const std::string& uri)
{
    class parse_handler: public uri_parse_handler
    {
        virtual void got_address(std::string& address)
        {
            (void)address;
        }
        virtual void got_param(std::string& key, std::string& value)
        {
            (void)key;
            (void)value;
        }
    } handler;
    return uri_parse(uri, handler);
}

decoded_uri uri_decode(const std::string& uri)
{
    class parse_handler: public uri_parse_handler
    {
    public:
        decoded_uri wip_;
        virtual void got_address(std::string& address)
        {
            if (wip_.address.set_encoded(address))
                wip_.has_address = true;
            else
                wip_.valid = false;
        }
        virtual void got_param(std::string& key, std::string& value)
        {
            if ("amount" == key)
            {
                wip_.amount = parse_amount(value);
                if (static_cast<uint64_t>(-1) != wip_.amount)
                    wip_.has_amount = true;
                else
                    wip_.valid = false;
            }
            else if ("label" == key)
            {
                wip_.label = std::move(value);
                wip_.has_label = true;
            }
            else if ("message" == key)
            {
                wip_.message = std::move(value);
                wip_.has_message = true;
            }
            else if ("r" == key)
            {
                wip_.r = std::move(value);
                wip_.has_r = true;
            }
            else if (!key.compare(0, 4, "req-"))
            {
                wip_.valid = false;
            }
        }
    } handler;
    if (!uri_parse(uri, handler))
        handler.wip_.valid = false;
    return handler.wip_;
}

/**
 * Validates an amount string according to the BIP 21 grammar.
 */
static bool check_amount(const std::string& amount)
{
    auto i = amount.begin();
    while (amount.end() != i && is_digit(*i))
        ++i;
    if (amount.end() != i && '.' == *i)
    {
        ++i;
        while (amount.end() != i && is_digit(*i))
            ++i;
    }
    return amount.end() == i;
}

uint64_t parse_amount(const std::string& amount)
{
    if (!check_amount(amount))
        return static_cast<uint64_t>(-1);
    // This code might have numerical problems:
    return static_cast<uint64_t>(100000000*strtod(amount.c_str(), nullptr));
}

} // namespace libwallet
