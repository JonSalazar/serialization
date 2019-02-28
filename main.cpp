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

    std::cout << hashMessage.ToString() << std::endl;

    // std::cout << txin.ToString() << std::endl;

    return 0;
}
// 0279e71392456e29e063036b5c95d544e5fd6df6b8e5d748176266e82e60552d74
// 124d1ab6f31467266d3552ae785d1794f841b10ca9c1cd913c8f4cd761d50bc8