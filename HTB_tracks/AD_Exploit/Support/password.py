'''
public static string getPassword()
{
	byte[] array = Convert.FromBase64String(enc_password);
	byte[] array2 = array;
	for (int i = 0; i < array.Length; i++)
	{
		array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
	}
	return Encoding.Default.GetString(array2);
}
'''

import base64

def get_password(enc_password: str) -> str:
    key = b"armando"
    array = base64.b64decode(enc_password)
    array2 = bytearray(len(array))

    for i in range(len(array)):
        array2[i] = (array[i] ^ key[i % len(key)]) ^ 0xDF

    return array2.decode('latin1')  # 'latin1' is often used for ANSI-compatible decoding


print(get_password('0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E'))



