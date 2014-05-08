/**
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
#ifndef LIBWALLET_STEALTH_HPP
#define LIBWALLET_STEALTH_HPP

#include <bitcoin/stealth.hpp>
#include <bitcoin/address.hpp>
#include <bitcoin/utility/ec_keys.hpp>
#include <wallet/define.hpp>

namespace libwallet {

using namespace libbitcoin;

class stealth_address
{
public:
    typedef std::vector<ec_point> pubkey_list;
    enum
    {
        reuse_key_option = 0x01
    };

    BCW_API uint8_t options() const;
    BCW_API const ec_point& scan_pubkey() const;
    BCW_API const pubkey_list& spend_pubkeys() const;
    BCW_API size_t number_signatures() const;
    BCW_API const stealth_prefix& prefix() const;

    BCW_API bool set_encoded(const std::string& encoded_address);

private:
    uint8_t options_ = 0;
    ec_point scan_pubkey_;
    pubkey_list spend_pubkeys_;
    size_t number_signatures_ = 0;
    stealth_prefix prefix_{0, 0};
};

BCW_API ec_point initiate_stealth(
    const ec_secret& ephem_privkey, const ec_point& scan_pubkey,
    const ec_point& spend_pubkey);
BCW_API ec_point uncover_stealth(
    const ec_point& ephem_pubkey, const ec_secret& scan_privkey,
    const ec_point& spend_pubkey);
BCW_API ec_secret uncover_stealth_secret(
    const ec_point& ephem_pubkey, const ec_secret& scan_privkey,
    const ec_secret& spend_privkey);

} // namespace libwallet

#endif

