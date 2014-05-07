#include <wallet/wallet.hpp>
#include <bitcoin/bitcoin.hpp>
using namespace libwallet;
using namespace bc;

int main()
{
    {
        ec_context ctx;
        ec_group group(ctx);
        hash_digest d = decode_hex_digest<hash_digest>(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
        ec_point Q = d * group;
        std::cout << "Q = dG = " << Q.encoded() << std::endl;
        hash_digest c = decode_hex_digest<hash_digest>(
            "298f44da9248962a7912e90e21922205b5072289d5c3d79cd6f83f1c880177b7");
        ec_point cG = c * group;
        ec_point Q_result_1 = Q + cG;
        std::cout << "Q' = Q + cG = " << Q_result_1.encoded() << std::endl;
        ec_point Q_result_2 = add_big_integers(d, c) * group;
        std::cout << "Q' = (d + c)G = " << Q_result_2.encoded() << std::endl;
    }
    std::cout << "----------------" << std::endl;
    ssl_ec_group group = EC_GROUP_new_by_curve_name(NID_secp256k1);

    if (!group)
        return -1;

    ssl_bn_ctx ctx = BN_CTX_new();

    // d = ...
    // Q = dG
    // c = ...
    // Q' = Q + cG
    // Q' = (d + c)G

    data_chunk d_data = decode_hex(
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    ssl_bignum d = BN_bin2bn(d_data.data(), (int)d_data.size(), nullptr);

    std::cout << "d = " << d_data << std::endl;

    ssl_ec_point Q = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Q, d, nullptr, nullptr, ctx))
        return -1;

    size_t Q_size = EC_POINT_point2oct(group, Q, POINT_CONVERSION_COMPRESSED,
        NULL, 0, ctx);
    data_chunk out(Q_size);
    if (!EC_POINT_point2oct(group, Q, POINT_CONVERSION_COMPRESSED,
        out.data(), out.size(), ctx))
        return -1;

    std::cout << "Q = dG = " << out << std::endl;

    data_chunk c_data = decode_hex(
        "298f44da9248962a7912e90e21922205b5072289d5c3d79cd6f83f1c880177b7");
    ssl_bignum c = BN_bin2bn(c_data.data(), (int)c_data.size(), nullptr);

    std::cout << "c = " << c_data << std::endl;

    ssl_ec_point Q_redux = EC_POINT_new(group);
    if (!EC_POINT_oct2point(group, Q_redux, out.data(), out.size(), ctx))
        return -1;

    ssl_ec_point cG = EC_POINT_new(group);
    if (!EC_POINT_mul(group, cG, c, nullptr, nullptr, ctx))
        return -1;
    ssl_ec_point Q_result_1 = EC_POINT_new(group);
    if (!EC_POINT_add(group, Q_result_1, Q_redux, cG, ctx))
        return -1;

    Q_size = EC_POINT_point2oct(group, Q_result_1, POINT_CONVERSION_COMPRESSED,
        NULL, 0, ctx);
    out.resize(Q_size);
    if (!EC_POINT_point2oct(group, Q_result_1, POINT_CONVERSION_COMPRESSED,
        out.data(), out.size(), ctx))
        return -1;

    std::cout << "Q' = Q + cG = " << out << std::endl;

    ssl_bignum d_plus_c = BN_new();
    if (!BN_add(d_plus_c, d, c))
        return -1;

    ssl_ec_point Q_result_2 = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Q_result_2, d_plus_c, nullptr, nullptr, ctx))
        return -1;

    Q_size = EC_POINT_point2oct(group, Q_result_2, POINT_CONVERSION_COMPRESSED,
        NULL, 0, ctx);
    out.resize(Q_size);
    if (!EC_POINT_point2oct(group, Q_result_2, POINT_CONVERSION_COMPRESSED,
        out.data(), out.size(), ctx))
        return -1;

    std::cout << "Q' = (d + c)G = " << out << std::endl;

#if 0
    ssl_ec_point Ki = EC_POINT_new(group);
    ssl_ec_point Kpar = EC_POINT_new(group);
    ssl_ec_point IL = EC_POINT_new(group);

    ssl_bignum il = BN_bin2bn(I.L.data(), (int)I.L.size(), nullptr);
    ssl_bignum n = BN_bin2bn(secp256k1_n.data(), (int)secp256k1_n.size(),
        nullptr);

    if (!ctx || !Ki || !Kpar || !IL || !il || !n)
        return -1;

    if (!EC_POINT_oct2point(group, Kpar, K_.data(), K_.size(), ctx))
        return -1;
    if (!EC_POINT_mul(group, IL, il, nullptr, nullptr, ctx))
        return -1;
    if (!EC_POINT_add(group, Ki, IL, Kpar, ctx))
        return -1;

    // The key is invalid if parse256(IL) >= n or Ki is at infinity:
    if (0 <= BN_cmp(il, n) || EC_POINT_is_at_infinity(group, Ki))
        return -1;

    size_t Ki_size = EC_POINT_point2oct(group, Ki, POINT_CONVERSION_COMPRESSED,
        NULL, 0, ctx);

    data_chunk out(Ki_size);
    if (!EC_POINT_point2oct(group, Ki, POINT_CONVERSION_COMPRESSED, out.data(),
        out.size(), ctx))
        return -1;
#endif

    return 0;
}

