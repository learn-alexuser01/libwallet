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

void reset(libwallet::uri_parse_result& result)
{
    result.address.reset();
    result.amount.reset();
    result.label.reset();
    result.message.reset();
    result.r.reset();
}

/**
 * Example class to demonstrate handling custom URI parameters.
 */
struct custom_result: public libwallet::uri_parse_result
{
    optional_string myparam;

protected:
    virtual bool got_param(std::string& key, std::string& value)
    {
        if ("myparam" == key)
            myparam.reset(value);
        return uri_parse_result::got_param(key, value);
    }
};

int main()
{
    libwallet::uri_parse_result result;
    bool success = false;

    // Typical-looking URI:
    success = libwallet::uri_parse(
        "bitcoin:113Pfw4sFqN1T5kXUnKbqZHMJHN9oyjtgD?amount=0.1", result);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(result.address &&
        result.address.get().encoded() == "113Pfw4sFqN1T5kXUnKbqZHMJHN9oyjtgD");
    BITCOIN_ASSERT(result.amount && result.amount.get() == 10000000);
    BITCOIN_ASSERT(!result.label);
    BITCOIN_ASSERT(!result.message);
    BITCOIN_ASSERT(!result.r);

    // Various scheme spellings and blank structure elements:
    BITCOIN_ASSERT( libwallet::uri_parse("bitcoin:", result));
    BITCOIN_ASSERT(!libwallet::uri_parse("bitcorn:", result));
    BITCOIN_ASSERT( libwallet::uri_parse("BITCOIN:?", result));
    BITCOIN_ASSERT( libwallet::uri_parse("Bitcoin:?&", result));
    BITCOIN_ASSERT(!libwallet::uri_parse("bitcOin:&", result));

    // Various blank parameter elements:
    BITCOIN_ASSERT( libwallet::uri_parse("bitcoin:?x=y", result));
    BITCOIN_ASSERT( libwallet::uri_parse("bitcoin:?x=", result));
    BITCOIN_ASSERT(!libwallet::uri_parse("bitcoin:?=y", result));
    BITCOIN_ASSERT(!libwallet::uri_parse("bitcoin:?=", result));
    BITCOIN_ASSERT( libwallet::uri_parse("bitcoin:?x", result));

    // Address only:
    reset(result);
    success = libwallet::uri_parse(
        "bitcoin:113Pfw4sFqN1T5kXUnKbqZHMJHN9oyjtgD", result);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(result.address &&
        result.address.get().encoded() == "113Pfw4sFqN1T5kXUnKbqZHMJHN9oyjtgD");
    BITCOIN_ASSERT(!result.amount);
    BITCOIN_ASSERT(!result.label);
    BITCOIN_ASSERT(!result.message);
    BITCOIN_ASSERT(!result.r);

    // Percent-encoding in address:
    reset(result);
    success = libwallet::uri_parse(
        "bitcoin:%3113Pfw4sFqN1T5kXUnKbqZHMJHN9oyjtgD", result);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(result.address &&
        result.address.get().encoded() == "113Pfw4sFqN1T5kXUnKbqZHMJHN9oyjtgD");

    // Malformed addresses:
    BITCOIN_ASSERT(!libwallet::uri_parse("bitcoin:19l88", result));
    BITCOIN_ASSERT(!libwallet::uri_parse("bitcoin:19z88", result));

    // Amount only:
    reset(result);
    success = libwallet::uri_parse("bitcoin:?amount=4.2", result);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(!result.address);
    BITCOIN_ASSERT(result.amount && result.amount.get() == 420000000);
    BITCOIN_ASSERT(!result.label);
    BITCOIN_ASSERT(!result.message);
    BITCOIN_ASSERT(!result.r);

    // Minimal amount:
    reset(result);
    success = libwallet::uri_parse("bitcoin:?amount=.", result);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(result.amount && result.amount.get() == 0);

    // Malformed amounts:
    BITCOIN_ASSERT(!libwallet::uri_parse("bitcoin:amount=4.2.1", result));
    BITCOIN_ASSERT(!libwallet::uri_parse("bitcoin:amount=bob", result));

    // Label only:
    reset(result);
    success = libwallet::uri_parse("bitcoin:?label=test", result);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(!result.address);
    BITCOIN_ASSERT(!result.amount);
    BITCOIN_ASSERT(result.label && result.label.get() == "test");
    BITCOIN_ASSERT(!result.message);
    BITCOIN_ASSERT(!result.r);

    // UTF-8 percent encoding:
    reset(result);
    success = libwallet::uri_parse("bitcoin:?label=%E3%83%95", result);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(result.label && result.label.get() == "フ");

    // Reserved symbol encoding and lowercase percent encoding:
    reset(result);
    success = libwallet::uri_parse("bitcoin:?label=%26%3d%6b", result);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(result.label && result.label.get() == "&=k");

    // Malformed percent encoding:
    BITCOIN_ASSERT(!libwallet::uri_parse("bitcoin:label=%3", result));
    BITCOIN_ASSERT(!libwallet::uri_parse("bitcoin:label=%3G", result));

    // Lenient parsing:
    reset(result);
    success = libwallet::uri_parse("bitcoin:?label=Some テスト", result, false);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(result.label && result.label.get() == "Some テスト");

    // Strict parsing:
    reset(result);
    success = libwallet::uri_parse("bitcoin:?label=Some テスト", result, true);
    BITCOIN_ASSERT(!success);

    // Message only:
    reset(result);
    success = libwallet::uri_parse("bitcoin:?message=Hi%20Alice", result);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(!result.address);
    BITCOIN_ASSERT(!result.amount);
    BITCOIN_ASSERT(!result.label);
    BITCOIN_ASSERT(result.message && result.message.get() == "Hi Alice");
    BITCOIN_ASSERT(!result.r);

    // Payment protocol only:
    reset(result);
    success = libwallet::uri_parse(
        "bitcoin:?r=http://www.example.com?purchase%3Dshoes", result);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(!result.address);
    BITCOIN_ASSERT(!result.amount);
    BITCOIN_ASSERT(!result.label);
    BITCOIN_ASSERT(!result.message);
    BITCOIN_ASSERT(result.r &&
        result.r.get() == "http://www.example.com?purchase=shoes");

    // Unknown optional parameter:
    reset(result);
    success = libwallet::uri_parse("bitcoin:?ignore=true", result);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(!result.address);
    BITCOIN_ASSERT(!result.amount);
    BITCOIN_ASSERT(!result.label);
    BITCOIN_ASSERT(!result.message);
    BITCOIN_ASSERT(!result.r);

    // Unknown required parameter:
    reset(result);
    success = libwallet::uri_parse("bitcoin:?req-ignore=false", result);
    BITCOIN_ASSERT(!success);

    // Custom parameter type:
    custom_result custom;
    success = libwallet::uri_parse("bitcoin:?myparam=here", custom);
    BITCOIN_ASSERT(success);
    BITCOIN_ASSERT(!custom.address);
    BITCOIN_ASSERT(!custom.amount);
    BITCOIN_ASSERT(!custom.label);
    BITCOIN_ASSERT(!custom.message);
    BITCOIN_ASSERT(!custom.r);
    BITCOIN_ASSERT(custom.myparam && custom.myparam.get() == "here");

    // Number parser:
    BITCOIN_ASSERT(libwallet::parse_amount("4.432") == 443200000);
    BITCOIN_ASSERT(
        libwallet::parse_amount("4.432.") == libwallet::invalid_amount);
    BITCOIN_ASSERT(libwallet::parse_amount("4")  == 400000000);
    BITCOIN_ASSERT(libwallet::parse_amount("4.") == 400000000);
    BITCOIN_ASSERT(libwallet::parse_amount(".4") == 40000000);
    BITCOIN_ASSERT(libwallet::parse_amount(".")  == 0);
    BITCOIN_ASSERT(libwallet::parse_amount("0.00000004")  == 4);
    BITCOIN_ASSERT(libwallet::parse_amount("0.000000049") == 4);
    BITCOIN_ASSERT(libwallet::parse_amount("4.432112345") == 443211234);
    BITCOIN_ASSERT(libwallet::parse_amount("21000000") == 2100000000000000);
    BITCOIN_ASSERT(libwallet::parse_amount("1234.9", 0) == 1234);
    BITCOIN_ASSERT(libwallet::parse_amount("64.25", 5) == 6425000);

    return 0;
}

