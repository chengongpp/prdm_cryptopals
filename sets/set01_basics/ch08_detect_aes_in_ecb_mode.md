# 检测ECB模式的AES加密

[这个文件]()包含了一堆使用hex编码过的密文。

其中有一个密文是使用ECB模式加密的。

请把它检出来。

谨记，ECB模式的缺陷在于，ECB模式无状态，且对同一个明文，其加密结果是固定的；同样的16字节明文，总是产生相同的16字节密文。