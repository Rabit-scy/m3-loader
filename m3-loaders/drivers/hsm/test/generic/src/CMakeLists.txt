set(st_hsm_test_SRCS
	CSE_AES_HW_test.c
	CSE_Boot_support_test.c
	CSE_Debug.c
	CSE_Debug_support_test.c
	CSE_ext_AES256_CCM_DVPT_TV.c
	CSE_ext_AES256_CCM_VADT_TV.c
	CSE_ext_AES256_CMAC_cmacGen_TV.c
	CSE_ext_AES256_CMAC_cmacVerif_TV.c
	CSE_ext_AES256_GCM_gcmEncrypt_TV.c
	CSE_ext_AES256_GCM_gcmDecrypt_TV.c
	CSE_ext_AES256_tests.c
	CSE_ext_ECC_ECDH_test.c
	CSE_ext_ECC_ECDH_Short_TV.c
	CSE_ext_ECC_ECDH_KeyPair_TV.c
	CSE_ext_ECC_ECDSA_SignVerify_brainpoolP256r1_TV.c
	CSE_ext_ECC_ECDSA_SignVerify_brainpoolP384r1_TV.c
	CSE_ext_ECC_ECDSA_SignVerify_P256_TV.c
	CSE_ext_ECC_ECDSA_SignVerify_P384_TV.c
	CSE_ext_ECC_ECDSA_SignVerify_P521_TV.c
	CSE_ext_ECC_ECDSA_SignVerif_brainpoolP256r1_TV.c
	CSE_ext_ECC_ECDSA_SignVerif_brainpoolP384r1_TV.c
	CSE_ext_ECC_ECDSA_SignVerif_P256_TV.c
	CSE_ext_ECC_ECDSA_SignVerif_P384_TV.c
	CSE_ext_ECC_ECDSA_SignVerif_P521_TV.c
	CSE_ext_ECC_ECDSA_test.c
	CSE_ext_ECC_ECIES_decrypt_TV.c
	CSE_ext_ECC_ECIES_encryptDecrypt_TV.c
	CSE_ext_ECC_ECIES_test.c
	CSE_ext_ECC_KeyPairGen_P256_TV.c
	CSE_ext_ECC_KeyPairGen_P384_TV.c
	CSE_ext_ECC_KeyPairGen_P521_TV.c
	CSE_ext_ECC_NVM_KEY_test.c
	CSE_ext_extendedDriverTests.c
	CSE_ext_extendedDriverTests_AES256.c
	CSE_ext_extendedDriverTests_ECC.c
	CSE_ext_extendedDriverTests_ECC_TV.c
	CSE_ext_extendedDriverTests_HMAC.c
	CSE_ext_extendedDriverTests_RSA.c
	CSE_ext_extendedDriverTests_RSA_TV.c
	CSE_ext_hash_test.c
	CSE_ext_HMAC_Restrict_TV.c
	CSE_ext_HMAC_RestrictKeySize_TV.c
	CSE_ext_HMAC_tests.c
	CSE_ext_HMAC_TV.c
	CSE_ext_OTP_test.c
	CSE_ext_RSA_PKCS_SIGN_SHAs_TV.c
	CSE_ext_RSA_PKCS_test.c
	CSE_ext_RSA_PKCS_TV.c
	CSE_ext_RSA_PKCS_VERIFY_SHAs_TV.c
	CSE_ext_test_globals.c
	CSE_ext_t3p_SecStorage.c
	CSE_ext_TLSv12_PRF_test.c
	CSE_ext_TLSv12_PRF_TV.c
	CSE_ext_UT_vectors.c
	CSE_extendKey_updateSupport.c
	CSE_Key_update.c
	CSE_Key_support_test.c
	CSE_internal_tests.c
	CSE_Manager_test.c
	CSE_NVM_KEY_test.c
	CSE_RAM_KEY_test.c
	CSE_RNG_test.c
	menu.c
	menu_ext.c
	serialprintf.c
	serial_input.c
	Test_CSE_HW.c
	test_support.c
	test_values.c
)

add_definitions(-DCSE_HSM)
add_library(hsmtest OBJECT ${st_hsm_test_SRCS})
