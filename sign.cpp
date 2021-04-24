#include <array>
#include <vector>
#include <ctime>
#include <cstring>

#include <openssl/hmac.h>
#include <openssl/sha.h>

static const char *_base64_enctbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const std::array<unsigned char, 128> _base64_dectbl =
    {{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
      255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
      255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62, 255, 255, 255, 63,
      52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 254, 255, 255,
      255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
      15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255, 255,
      255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
      41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 255, 255, 255, 255, 255}};
struct _triple_byte
{
    unsigned char _1_1 : 2;
    unsigned char _0 : 6;
    unsigned char _2_1 : 4;
    unsigned char _1_2 : 4;
    unsigned char _3 : 6;
    unsigned char _2_2 : 2;
};

bool is_ascii(char c)
{
    return static_cast<signed char>(c) >= 0;
}

std::vector<unsigned char> from_base64(const std::string &input)
{
    std::vector<unsigned char> result;

    if (input.empty())
        return result;

    size_t padding = 0;

    // Validation
    {
        auto size = input.size();

        if ((size % 4) != 0)
        {
            throw std::runtime_error("length of base64 string is not an even multiple of 4");
        }

        for (auto iter = input.begin(); iter != input.end(); ++iter, --size)
        {
            const auto ch = *iter;
            if (!is_ascii(ch))
            {
                throw std::runtime_error("invalid character found in base64 string");
            }
            const size_t ch_sz = static_cast<size_t>(ch);
            if (ch_sz >= _base64_dectbl.size() || _base64_dectbl[ch_sz] == 255)
            {
                throw std::runtime_error("invalid character found in base64 string");
            }
            if (_base64_dectbl[ch_sz] == 254)
            {
                padding++;
                // padding only at the end
                if (size > 2)
                {
                    throw std::runtime_error("invalid padding character found in base64 string");
                }
                if (size == 2)
                {
                    const auto ch2 = *(iter + 1);
                    if (!is_ascii(ch2))
                    {
                        throw std::runtime_error("invalid padding character found in base64 string");
                    }
                    const size_t ch2_sz = static_cast<size_t>(ch2);
                    if (ch2_sz >= _base64_dectbl.size() || _base64_dectbl[ch2_sz] != 254)
                    {
                        throw std::runtime_error("invalid padding character found in base64 string");
                    }
                }
            }
        }
    }

    auto size = input.size();
    const char *ptr = &input[0];

    auto outsz = (size / 4) * 3;
    outsz -= padding;

    result.resize(outsz);

    size_t idx = 0;
    for (; size > 4; ++idx)
    {
        unsigned char target[3];
        std::memset(target, 0, sizeof(target));
        _triple_byte *record = reinterpret_cast<_triple_byte *>(target);

        unsigned char val0 = _base64_dectbl[ptr[0]];
        unsigned char val1 = _base64_dectbl[ptr[1]];
        unsigned char val2 = _base64_dectbl[ptr[2]];
        unsigned char val3 = _base64_dectbl[ptr[3]];

        record->_0 = val0;
        record->_1_1 = val1 >> 4;
        result[idx] = target[0];

        record->_1_2 = val1 & 0xF;
        record->_2_1 = val2 >> 2;
        result[++idx] = target[1];

        record->_2_2 = val2 & 0x3;
        record->_3 = val3 & 0x3F;
        result[++idx] = target[2];

        ptr += 4;
        size -= 4;
    }

    // Handle the last four bytes separately, to avoid having the conditional statements
    // in all the iterations (a performance issue).
    {
        unsigned char target[3];
        std::memset(target, 0, sizeof(target));
        _triple_byte *record = reinterpret_cast<_triple_byte *>(target);

        unsigned char val0 = _base64_dectbl[ptr[0]];
        unsigned char val1 = _base64_dectbl[ptr[1]];
        unsigned char val2 = _base64_dectbl[ptr[2]];
        unsigned char val3 = _base64_dectbl[ptr[3]];

        record->_0 = val0;
        record->_1_1 = val1 >> 4;
        result[idx] = target[0];

        record->_1_2 = val1 & 0xF;
        if (val2 != 254)
        {
            record->_2_1 = val2 >> 2;
            result[++idx] = target[1];
        }
        else
        {
            // There shouldn't be any information (ones) in the unused bits,
            if (record->_1_2 != 0)
            {
                throw std::runtime_error("Invalid end of base64 string");
            }
            return result;
        }

        record->_2_2 = val2 & 0x3;
        if (val3 != 254)
        {
            record->_3 = val3 & 0x3F;
            result[++idx] = target[2];
        }
        else
        {
            // There shouldn't be any information (ones) in the unused bits.
            if (record->_2_2 != 0)
            {
                throw std::runtime_error("Invalid end of base64 string");
            }
            return result;
        }
    }

    return result;
}

std::string to_base64(const unsigned char *input, size_t size)
{
    auto ptr = input;

    std::string result;
    result.reserve((size / 3 + 1) * 4);

    for (; size >= 3;)
    {
        const _triple_byte *record = reinterpret_cast<const _triple_byte *>(ptr);
        unsigned char idx0 = record->_0;
        unsigned char idx1 = (record->_1_1 << 4) | record->_1_2;
        unsigned char idx2 = (record->_2_1 << 2) | record->_2_2;
        unsigned char idx3 = record->_3;
        result.push_back(char(_base64_enctbl[idx0]));
        result.push_back(char(_base64_enctbl[idx1]));
        result.push_back(char(_base64_enctbl[idx2]));
        result.push_back(char(_base64_enctbl[idx3]));
        size -= 3;
        ptr += 3;
    }

    switch (size)
    {
    case 1:
    {
        const _triple_byte *record = reinterpret_cast<const _triple_byte *>(ptr);
        unsigned char idx0 = record->_0;
        unsigned char idx1 = (record->_1_1 << 4);
        result.push_back(char(_base64_enctbl[idx0]));
        result.push_back(char(_base64_enctbl[idx1]));
        result.push_back('=');
        result.push_back('=');
        break;
    }
    case 2:
    {
        const _triple_byte *record = reinterpret_cast<const _triple_byte *>(ptr);
        unsigned char idx0 = record->_0;
        unsigned char idx1 = (record->_1_1 << 4) | record->_1_2;
        unsigned char idx2 = (record->_2_1 << 2);
        result.push_back(char(_base64_enctbl[idx0]));
        result.push_back(char(_base64_enctbl[idx1]));
        result.push_back(char(_base64_enctbl[idx2]));
        result.push_back('=');
        break;
    }
    }

    return result;
}

std::string to_base64(const std::vector<unsigned char> &input)
{
    return to_base64(&input[0], input.size());
}

std::string get_url_path(const std::string &url)
{
    auto pos = url.find_first_of(":");
    if (pos != std::string::npos)
    {
        pos = url.find_first_of("/", pos + 3);
        if (pos == std::string::npos)
        {
            return "";
        }
        else
        {
            return url.substr(pos + 1);
        }
    }
    else
    {
        pos = url.find_first_of("/");
        if (pos == std::string::npos)
        {
            return "";
        }
        else
        {
            return url.substr(pos + 1);
        }
    }
}

std::string azure_hash(const std::string &to_sign, const std::vector<unsigned char> &key)
{
    unsigned int digest_length = SHA256_DIGEST_LENGTH;
    unsigned char digest[SHA256_DIGEST_LENGTH];

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key.data(), static_cast<int>(key.size()), EVP_sha256(), NULL);
    HMAC_Update(&ctx, (const unsigned char *)to_sign.c_str(), to_sign.size());
    HMAC_Final(&ctx, digest, &digest_length);
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_CTX_reset(ctx);
    HMAC_Init_ex(ctx, key.data(), static_cast<int>(key.size()), EVP_sha256(), NULL);
    HMAC_Update(ctx, (const unsigned char *)to_sign.c_str(), to_sign.size());
    HMAC_Final(ctx, digest, &digest_length);
    HMAC_CTX_free(ctx);
#endif

    return to_base64(std::vector<unsigned char>(digest, digest + digest_length));
}

std::string get_ms_date()
{
    std::time_t t = std::time(nullptr);
    std::tm *pm;
    pm = std::gmtime(&t);

    static const char *weekdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    std::string rfc_1123_format = "%a, %d %b %Y %H:%M:%S GMT";
    rfc_1123_format.replace(rfc_1123_format.find("%a"), 2, weekdays[pm->tm_wday]);
    rfc_1123_format.replace(rfc_1123_format.find("%b"), 2, months[pm->tm_mon]);
    char buf[32];
    std::strftime(buf, sizeof(buf), rfc_1123_format.data(), pm);
    return std::string(buf);
}

std::string azure_sign(const std::string &url,
                       const std::string &ms_date,
                       const std::string &ms_version,
                       const std::string &account_name,
                       const std::string &account_key)
{
    std::string string_to_sign("GET");
    string_to_sign.append("\n");

    string_to_sign.append("").append("\n");
    string_to_sign.append("").append("\n");
    string_to_sign.append("").append("\n");
    string_to_sign.append("").append("\n");
    string_to_sign.append("").append("\n");
    // TODO: add date to string_to_sign when date is supported.
    string_to_sign.append("\n"); // Date
    string_to_sign.append("").append("\n");
    string_to_sign.append("").append("\n");
    string_to_sign.append("").append("\n");
    string_to_sign.append("").append("\n");
    string_to_sign.append("\n"); // Range

    string_to_sign.append("x-ms-date:").append(ms_date).append("\n");
    string_to_sign.append("x-ms-version:").append(ms_version).append("\n");

    string_to_sign.append("/").append(account_name).append("/").append(get_url_path(url));

    return "SharedKey " + account_name + ":" + azure_hash(string_to_sign, from_base64(account_key));
    //return fmt::format("SharedKey {}:{}", account_name, );
}