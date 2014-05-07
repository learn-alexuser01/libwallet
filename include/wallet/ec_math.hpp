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
#ifndef LIBBITCOIN_EC_MATH_HPP
#define LIBBITCOIN_EC_MATH_HPP

#include <wallet/define.hpp>
#ifdef USE_OPENSSL_EC
    #include <openssl/ec.h>
#endif
#ifdef USE_OPENSSL_BN
    #include <openssl/bn.h>
#endif
#include <bitcoin/types.hpp>

namespace libwallet {

using libbitcoin::hash_digest;
using libbitcoin::data_chunk;

template<typename T, void destroy(T* p)>
class auto_free
{
public:
    auto_free(T* p)
      : ptr(p)
    {
    }
    ~auto_free()
    {
        destroy(ptr);
    }
    operator T*()
    {
        return ptr;
    }
    T* ptr;
};

typedef auto_free<BIGNUM, BN_free> ssl_bignum;
typedef auto_free<BN_CTX, BN_CTX_free> ssl_bn_ctx;

typedef auto_free<EC_GROUP, EC_GROUP_free> ssl_ec_group;
typedef auto_free<EC_POINT, EC_POINT_free> ssl_ec_point;

// ****************************************************************************

struct BCW_API point_result
{
    EC_POINT* point;
    BN_CTX* ctx;
    EC_GROUP* group;
};

struct BCW_API ec_context
{
    ssl_bn_ctx ctx_ = BN_CTX_new();
};

class ec_group
{
public:
    BCW_API ec_group(ec_context& ctx);

private:
    friend point_result operator*(const hash_digest& integer, ec_group& group);
    BN_CTX* ctx_;
    ssl_ec_group group_ = EC_GROUP_new_by_curve_name(NID_secp256k1);
};

class ec_point
{
public:
    BCW_API ec_point(point_result result);
    BCW_API data_chunk encoded();

private:
    friend point_result operator+(ec_point& point_a, ec_point& point_b);
    BN_CTX* ctx_;
    EC_GROUP* group_;
    ssl_ec_point point_;
};

BCW_API point_result operator*(const hash_digest& integer, ec_group& group);
BCW_API point_result operator+(ec_point& point_a, ec_point& point_b);
BCW_API hash_digest add_big_integers(
    const hash_digest& int_a, const hash_digest& int_b);

} // libwallet

#endif

