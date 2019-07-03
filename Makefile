#author AngelToms
CXX_FLAGS	:=	c++
C_FLAGS		:= cc
C_LIBS		:=
C_INCLUDES	:=	-I./ElfParser	-I./Utils   -I./Crypt	-I./ShellCode	-I./Builder

all	: elfbuilder

objs	:=	ElfParser/ElfParser.o			\
		ElfParser/ElfRelUtil.o			\
		ElfParser/ElfDynsymUtil.o		\
		ElfParser/ElfInitArrayUtil.o		\
		ElfParser/ElfDynstrUtil.o		\
		ElfParser/ElfRodataUtil.o		\
		ElfParser/ElfBssUtil.o			\
		Builder/ElfBuilder.o			\
		Builder/ElfEncDynstrBuilder.o		\
		Builder/ElfEncRodataBuilder.o		\
		ShellCode/ShellCode.o			\
		ShellCode/EncryptDynstrShellCode.o	\
		ShellCode/EncryptRodataShellCode.o	\
		Utils/SysUtil.o				\
		Utils/StringUtil.o			\
		Crypt/Cryptor.o				\
		Crypt/Xor.o				\
		Crypt/StrangeChar.o			\
		Crypt/AsciiChange.o			\
		HexLog.o				\
		Main.o
	
elfbuilder: $(objs)

	g++ $(objs) -o elfbuilder $(C_LIBS) $(C_INCLUDES)

clean:
	rm -rf *.o elfbuilder elfbuilder.exe ElfParser/*.o Utils/*.o Crypt/*.o ShellCode/*.o Builder/*.o
		

		
	