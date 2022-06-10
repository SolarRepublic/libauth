FROM emscripten/emsdk:3.1.13

RUN apt-get update \
  && apt-get install -y \
  autoconf \
  libtool \
  build-essential

COPY wasm /libauth/wasm

WORKDIR /libauth/wasm/secp256k1

RUN ./autogen.sh
RUN emconfigure ./configure  \
  --enable-module-ecdh  \
  --enable-module-recovery  \
  --enable-module-extrakeys  \
  --enable-module-schnorrsig  \
  # uncomment next line for debug build:
#   CFLAGS="-g -O0"
  # uncomment next line for production build: \
  CFLAGS="-O3"

RUN emmake make FORMAT=wasm
RUN mkdir -p out/secp256k1

RUN emcc src/libsecp256k1_la-secp256k1.o  \
    src/libsecp256k1_precomputed_la-precomputed_ecmult.o \
    src/libsecp256k1_precomputed_la-precomputed_ecmult_gen.o \
  # uncomment next line for debug build:
#   -O0 -g4 -s ASSERTIONS=2 --source-map-base ../../../wasm/secp256k1 \
  # uncomment next line for production build:
  -O3 \
  -s WASM=1 \
  -s "BINARYEN_METHOD='native-wasm'" \
  -s STANDALONE_WASM --no-entry \
  -s DETERMINISTIC=1 \
  -s EXPORTED_FUNCTIONS='[ \
  "_malloc", \
  "_free", \
  "_secp256k1_context_create", \
  "_secp256k1_context_randomize", \
  "_secp256k1_ec_seckey_verify", \
  "_secp256k1_ec_privkey_tweak_add", \
  "_secp256k1_ec_privkey_tweak_mul", \
  "_secp256k1_ec_pubkey_create", \
  "_secp256k1_ec_pubkey_parse", \
  "_secp256k1_ec_pubkey_serialize", \
  "_secp256k1_ec_pubkey_tweak_add", \
  "_secp256k1_ec_pubkey_tweak_mul", \
  "_secp256k1_ecdh", \
  "_secp256k1_ecdsa_recover", \
  "_secp256k1_ecdsa_recoverable_signature_serialize_compact", \
  "_secp256k1_ecdsa_recoverable_signature_parse_compact", \
  "_secp256k1_ecdsa_sign", \
  "_secp256k1_ecdsa_signature_normalize", \
  "_secp256k1_ecdsa_signature_parse_der", \
  "_secp256k1_ecdsa_signature_parse_compact", \
  "_secp256k1_ecdsa_signature_serialize_der", \
  "_secp256k1_ecdsa_signature_serialize_compact", \
  "_secp256k1_ecdsa_sign_recoverable", \
  "_secp256k1_ecdsa_verify", \
  "_secp256k1_schnorrsig_sign", \
  "_secp256k1_schnorrsig_verify" \
  ]' \
  -o out/secp256k1/secp256k1.js

RUN OUTPUT_TS_FILE=out/secp256k1/secp256k1.base64.ts; printf "/**\n * @hidden\n */\n// prettier-ignore\nexport const secp256k1Base64Bytes =\n  '" > $OUTPUT_TS_FILE && base64 -w 0 out/secp256k1/secp256k1.wasm >> $OUTPUT_TS_FILE && printf "';\n" >> $OUTPUT_TS_FILE

RUN cp -r /libauth/wasm/secp256k1/out /libauth/bin

# copy outputs to mounted volume
CMD ["cp", "-r", "/libauth/bin", "/libauth/out"]