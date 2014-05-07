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
#include <wallet/ec_math.hpp>

#include <bitcoin/utility/assert.hpp>
#include <bitcoin/constants.hpp>

namespace libwallet {

using libbitcoin::null_hash;

BCW_API ec_group::ec_group(ec_context& ctx)
  : ctx_(ctx.ctx_)
{
    BITCOIN_ASSERT(group_);
}

BCW_API ec_point::ec_point(point_result result)
  : ctx_(result.ctx), group_(result.group), point_(result.point)
{
    BITCOIN_ASSERT(result.point);
}

BCW_API data_chunk ec_point::encoded()
{
    BITCOIN_ASSERT(ctx_);
    BITCOIN_ASSERT(group_);
    BITCOIN_ASSERT(point_.ptr);
    size_t size = EC_POINT_point2oct(group_, point_,
        POINT_CONVERSION_COMPRESSED, NULL, 0, ctx_);
    data_chunk result(size);
    if (!EC_POINT_point2oct(group_, point_,
        POINT_CONVERSION_COMPRESSED, result.data(), result.size(), ctx_))
    {
        return data_chunk();
    }
    return result;
}

BCW_API point_result operator*(const hash_digest& integer, ec_group& group)
{
    ssl_bignum bignum = BN_bin2bn(
        integer.data(), (int)integer.size(), nullptr);
    EC_POINT* result = EC_POINT_new(group.group_);
    if (!EC_POINT_mul(group.group_, result, bignum,
        nullptr, nullptr, group.ctx_))
    {
        return {nullptr, nullptr, nullptr};
    }
    return {result, group.ctx_, group.group_};
}

BCW_API point_result operator+(ec_point& point_a, ec_point& point_b)
{
    BN_CTX* ctx = point_a.ctx_;
    EC_GROUP* group = point_a.group_;
    EC_POINT* result = EC_POINT_new(group);
    if (!EC_POINT_add(group, result, point_a.point_, point_b.point_, ctx))
        return {nullptr, nullptr, nullptr};
    return {result, ctx, group};
}

BCW_API hash_digest add_big_integers(
    const hash_digest& int_a, const hash_digest& int_b)
{
    // a + b = c
    ssl_bignum a = BN_bin2bn(int_a.data(), (int)int_a.size(), nullptr);
    ssl_bignum b = BN_bin2bn(int_b.data(), (int)int_b.size(), nullptr);
    ssl_bignum c = BN_new();
    if (!BN_add(c, a, b))
        return null_hash;
    hash_digest result;
    int c_size = BN_num_bytes(c);
    if (c_size != BN_bn2bin(c, &result[result.size() - c_size]))
        return null_hash;
    return result;
}

} // libwallet

