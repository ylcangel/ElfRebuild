# ElfRebuild
crypt elf dynstr or rodata section
ElfRebuilder.zip -- 源代码

功能描述： 基于init_array的字符串表或rodata节加密。
		此代码包含两部分实现： 1、导出表对应字符串表加密
							           2、rodata解密
							   
编译环境：
	你可以选择cygwin 或者linux 都可以，编译后会生成一个exe 名字为elfbuilder。
	
用法：
	elfbuilder -t [dynstr | rodata] libxxx.so
	
	选项： dynstr 或者 rodata 为可选项，只能选择一个，dynstr为对导出表对应字符串表加密， rodata为对常量字符串表加密。
	
执行结果：
	最终生成一个libxxx.so.1
	

注意：
	shellcode中已经flash cache。
	
目前兼容：
	32位的arm平台 ，只实现了armv5的shellcode。
  
  
  因为代码是几年前的，所以代码风格可能不是很好，请大家见谅！
