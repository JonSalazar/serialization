#include <iostream>
#include "sha256.h"
#include "uint256.h"
#include "serialize.h"
#include "version.h"
#include "primitives/transaction.h"

/* ----------- XSN Hash ------------------------------------------------- */
/** A hasher class for XSN's 256-bit hash (double SHA-256). */
class CHash256 {
private:
    CSHA256 sha;
public:
    static const size_t OUTPUT_SIZE = CSHA256::OUTPUT_SIZE;

    void Finalize(unsigned char hash[OUTPUT_SIZE]) {
        unsigned char buf[CSHA256::OUTPUT_SIZE];
        sha.Finalize(buf);
        sha.Reset().Write(buf, CSHA256::OUTPUT_SIZE).Finalize(hash);
    }

    CHash256& Write(const unsigned char *data, size_t len) {
        sha.Write(data, len);
        return *this;
    }

    CHash256& Reset() {
        sha.Reset();
        return *this;
    }
};

/** A writer stream (for serialization) that computes a 256-bit hash. */
class CHashWriter
{
private:
    CHash256 ctx;
    const int nType;
    const int nVersion;
public:


    CHashWriter(int nTypeIn, int nVersionIn) : nType(nTypeIn), nVersion(nVersionIn) {}

    int GetType() const { return nType; }
    int GetVersion() const { return nVersion; }

    void write(const char *pch, size_t size) {
        ctx.Write((const unsigned char*)pch, size);
    }

    // invalidates the object
    uint256 GetHash() {
        uint256 result;
        ctx.Finalize((unsigned char*)&result);
        return result;
    }

    template<typename T>
    CHashWriter& operator<<(const T& obj) {
        // Serialize to this stream
        ::Serialize(*this, obj);
        return (*this);
    }
};

signed char getHexDigit(char c)
{
    unsigned char uc = c;
    if (uc >= '0' && uc <= '9')
        return uc - '0';
    if (uc >= 'A' && uc <= 'F')
        return uc - 'A' + 10;
    if (uc >= 'a' && uc <= 'f')
        return uc - 'a' + 10;
    
    return -1;
}

void serializeTxInput(const char* psz, char* data, uint32_t width)
{
    memset(data, 0, sizeof(data));

    // skip leading spaces
    while (isspace(*psz))
        psz++;

    // skip 0x
    if (psz[0] == '0' && tolower(psz[1]) == 'x')
        psz += 2;

    // hex string to uint
    const char* pbegin = psz;
    while (getHexDigit(*psz) != -1)
        psz++;
    psz--;
    unsigned char* p1 = (unsigned char*)data;
    unsigned char* pend = p1 + width;
    while (psz >= pbegin && p1 < pend) {
        *p1 = getHexDigit(*psz--);
        if (psz >= pbegin) {
            *p1 |= ((unsigned char)::getHexDigit(*psz--) << 4);
            p1++;
        }
    }
}

void custom(const std::string txid, uint32_t nout) {
    char buff[ 32 ];
    serializeTxInput(txid.c_str(), buff, 32);
    
    std::cout << "serial:" << std::endl;
    for (int i = 0; i < 32; i++) {
        std::cout << static_cast<uint32_t>(*(buff + i)) % 256 << " ";
    }
    std::cout << std::endl;

    char* ptrout = (char*)&nout;
    for (int i = 0; i < 4; i++) {
        std::cout << static_cast<uint32_t>(*(ptrout + i)) % 256 << " ";
    }
    std::cout << std::endl;
}

/** Compute the 256-bit hash of an object's serialization. */
template<typename T>
uint256 SerializeHash(const T& obj, int nType=SER_GETHASH, int nVersion=PROTOCOL_VERSION)
{
    CHashWriter ss(nType, nVersion);
    ss << obj;
    return ss.GetHash();
}

int main(int argc, char** argv) {

    CMutableTransaction tx;
    tx.nVersion = 2;

    std::string txid = "358d8c9c2a8843cce58a7c35158f32213e1725d8c08e35a5b56ff319affe9ac9";
    uint256 lastTx = uint256S(txid);
    
    CTxIn txin(lastTx, 1);
    tx.vin.push_back(txin);
    auto firstInput = tx.vin.front().prevout;
    auto hashMessage = SerializeHash(firstInput);

    std::cout << "hash message to string" << std::endl;
    std::cout << hashMessage.ToString() << std::endl;
    std::cout << std::endl;

    std::cout << "txin to string" << std::endl;
    std::cout << txin.ToString() << std::endl;
    std::cout << std::endl;

    custom(txid, 1);

    return 0;
}
// 0279e71392456e29e063036b5c95d544e5fd6df6b8e5d748176266e82e60552d74
// 124d1ab6f31467266d3552ae785d1794f841b10ca9c1cd913c8f4cd761d50bc8

/**
 * 
 * exStr(std::reverse_iterator<const uint8_t*>(data + sizeof(data)), std::reverse_iterator<const uint8_t*>(data));
**/


// serial uint32_t
// 4294967241 4294967194 4294967294 4294967215 25 4294967283 111 4294967221 4294967205 53 4294967182 4294967232 4294967256 37 23 62 33 50 4294967183 21 53 124 4294967178 4294967269 4294967244 67 4294967176 42 4294967196 4294967180 4294967181 53
// serial char
// 201 154 254 175 25 243 111 181 165 53 142 192 216 37 23 62 33 50 143 21 53 124 138 229 204 67 136 42 156 140 141 53 1 0 0 0

// hash
// d170716c16d1cff50af4fcaf468dd2638d2da3aaccedefc7bdd048780991d069
// hash bytes
// 105 208 145 9 120 72 208 189 199 239 237 204 170 163 45 141 99 210 141 70 175 252 244 10 245 207 209 22 108 113 112 209

// outing.txt (from trezor-mcu)
// 105 208 145 9 120 72 208 189 199 239 237 204 170 163 45 141 99 210 141 70 175 252 244 10 245 207 209 22 108 113 112 209 