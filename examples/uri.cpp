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
/*
  Demonstration of URI utilities.
*/
#include <bitcoin/bitcoin.hpp>
#include <wallet/wallet.hpp>
#include <iostream>

void test_uri_parse(std::string uri, bool strict=true)
{
    std::cout << "parse URI: \"" << uri << "\"" << std::endl;
    class parse_handler: public libwallet::uri_parse_handler
    {
        virtual void got_address(std::string& address)
        {
            std::cout << "    got address: \"" << address << "\"" << std::endl;
        }
        virtual void got_param(std::string& key, std::string& value)
        {
            std::cout << "    got parameter: \"" << key << "\" = \"" <<
                value << "\"" << std::endl;
        }
    } handler;
    if (libwallet::uri_parse(uri, handler, strict))
        std::cout << "    ok" << std::endl;
    else
        std::cout << "    error" << std::endl;
}

void test_uri_decode(std::string uri, bool strict=true)
{
    libwallet::decoded_uri out = libwallet::uri_decode(uri, strict);
    std::cout << "decode URI: \"" << uri << "\"" << std::endl;
    if (!out.valid)
        std::cout << "    invalid" << std::endl;
    if (out.has_address)
        std::cout << "    address: " << out.address.encoded() << std::endl;
    if (out.has_amount)
        std::cout << "    amount: " << out.amount << std::endl;
    if (out.has_label)
        std::cout << "    label: \"" << out.label << "\"" << std::endl;
    if (out.has_message)
        std::cout << "    message: \"" << out.message << "\"" << std::endl;
    if (out.has_r)
        std::cout << "    r: \"" << out.r << "\"" << std::endl;
}

int main()
{
    BITCOIN_ASSERT(libwallet::parse_amount("4.432") == 443200000);
    BITCOIN_ASSERT(
        libwallet::parse_amount("4.432.") == libwallet::invalid_amount);
    BITCOIN_ASSERT(libwallet::parse_amount("45.432") == 4543200000);
    BITCOIN_ASSERT(libwallet::parse_amount("4.432112345") == 443211234);
    BITCOIN_ASSERT(libwallet::parse_amount("4") == 400000000);
    BITCOIN_ASSERT(libwallet::parse_amount(".") == 0);

    test_uri_parse("bitcoin:113Pfw4sFqN1T5kXUnKbqZHMJHN9oyjtgD?label=test");
    test_uri_parse("bitcoin:");
    test_uri_parse("bitcorn:");
    test_uri_parse("BITCOIN:?");
    test_uri_parse("Bitcoin:?&");
    test_uri_parse("bitcOin:&");
    test_uri_parse("bitcoin:?x=y");
    test_uri_parse("bitcoin:?x=");
    test_uri_parse("bitcoin:?=y");
    test_uri_parse("bitcoin:?=");
    test_uri_parse("bitcoin:?x");
    test_uri_parse("bitcoin:19z88");
    test_uri_parse("bitcoin:19l88");
    test_uri_parse("bitcoin:19z88?x=http://www.example.com?purchase%3Dshoes");
    test_uri_parse("bitcoin:19z88?name=%E3%83%95"); // UTF-8
    test_uri_parse("bitcoin:19z88?name=%3");
    test_uri_parse("bitcoin:19z88?name=%3G");
    test_uri_parse("bitcoin:19z88?name=%3f");
    test_uri_parse("bitcoin:%31");
    test_uri_parse("bitcoin:?label=Some テスト");
    test_uri_parse("bitcoin:?label=Some テスト", false);

    std::cout << "================================" << std::endl;

    test_uri_decode("bitcoin:113Pfw4sFqN1T5kXUnKbqZHMJHN9oyjtgD");
    test_uri_decode("bitcoin:19z88");
    test_uri_decode("bitcoin:?=");
    test_uri_decode("bitcoin:?amount=4.2");
    test_uri_decode("bitcoin:?amount=.");
    test_uri_decode("bitcoin:?amount=4.2.4");
    test_uri_decode("bitcoin:?amount=foo");
    test_uri_decode("bitcoin:?label=Bob");
    test_uri_decode("bitcoin:?message=Hi%20Alice");
    test_uri_decode("bitcoin:?r=http://www.example.com?purchase%3Dshoes");
    test_uri_decode("bitcoin:?foo=ignore");
    test_uri_decode("bitcoin:?req-foo=die");
    test_uri_decode("bitcoin:?label=テスト");
    test_uri_decode("bitcoin:?label=テスト", false);

    return 0;
}

