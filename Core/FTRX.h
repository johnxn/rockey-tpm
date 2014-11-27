#ifndef _FTRX_H
#define _FTRX_H

typedef unsigned int     DWORD;
typedef unsigned short   WORD;
typedef unsigned char    BYTE;

#define PIN_NONE        0x00 //����̬
#define PIN_USER        0x01 //�û�̬
#define PIN_ADMIN       0x02 //������̬

#define LED_OFF			0x00 //����
#define LED_ON			0x01 //����
#define LED_BLINK		0x02 //����

#define MODE_ENCODE      0   //����
#define MODE_DECODE      1   //����

#define FILE_DATA                 1 //��ͨ�����ļ�
#define FILE_PRIKEY_RSA           2 //RSA˽Կ�ļ�
#define FILE_PRIKEY_ECCSM2        3 //ECC��SM2˽Կ�ļ�
#define FILE_KEY                  4 //SM4��3DES��Կ�ļ�
#define FILE_EXE                  5 //��ִ���ļ�

//ͨ��
#define ERR_SUCCESS           0x9000  //�����ɹ�
#define ERR_INVALID_INS       0x6C00  //��Ч��INS
#define ERR_INVALID_P1        0x6C01  //��Ч��P1
#define ERR_INVALID_P2        0x6C02  //��Ч��P2
#define ERR_INVALID_LEN       0x6C03  //��Ч��LEN
#define ERR_INVALID_PARAM     0x6C04  //��Ч�Ĳ���(��:�����е�һЩ����)
#define ERR_FAILED            0x6C05  //����ʧ��

//��д����
#define ERR_READ_ERR          0x6B00  //�����ݴ���
#define ERR_WRITE_ERR         0x6B01  //д���ݴ���

//�ļ�ϵͳ
#define ERR_FILE_EXIST        0x6A82  //�ļ��Ѵ���
#define ERR_FILE_NOTFOUND     0x6A83  //�ļ�������
#define ERR_FILE_CFILE_ERR    0x6A86  //�����ļ�ʧ��
#define ERR_FILE_READ_ERR     0x6A87  //���ļ�ʧ��
#define ERR_FILE_WRITE_ERR    0x6A88  //д�ļ�ʧ��
#define ERR_FILE_DFILE_ERR    0x6A89  //ɾ�ļ�ʧ��
#define ERR_FILE_CDIR_ERR     0x6A8A  //�����ļ���ʧ��
#define ERR_FILE_DDIR_ERR     0x6A8B  //ɾ���ļ���ʧ��

//Ȩ�����
#define ERR_NOT_INITED        0x6980  //��δ��ʼ��
#define ERR_ALREADY_INITED    0x6981  //�ѳ�ʼ������
#define ERR_ADMINPIN_NOTCHECK 0x6982  //����ԱPINû��У��
#define ERR_USERPIN_NOTCHECK  0x6983  //�û�PINû��У��
#define ERR_PIN_BLOCKED       0x6984  //PIN���ѱ�����
#define ERR_RUN_LIMITED       0x6985  //����������(��:˽Կ���㡢����������)

//������Ϣ
typedef struct
{	
	unsigned short  m_Ver;               //COS�汾,����:0x0201,��ʾ2.01�� 
	unsigned short  m_Type;              //Ӳ������: 0xFF��ʾ��׼��, 0x00��ʾʱ����, 0x02��ʾ��׼U����   
	unsigned char   m_BirthDay[8];       //��������
	unsigned long   m_Agent;             //�����̱��,����:Ĭ�ϵ�0x00000000
	unsigned long   m_PID;               //��ƷID
	unsigned long   m_UserID;            //�û�ID
	unsigned char   m_HID[8];            //8�ֽڵ�Ӳ��ID
	unsigned long   m_IsMother;          //ĸ����־: 0x01��ʾ��ĸ��, 0x00��ʾ����ĸ��     
	
} DONGLE_INFO;

//�����ļ���Ȩ�ṹ
typedef struct
{
	unsigned short  m_Read_Priv;      //��Ȩ��: 0Ϊ��С����Ȩ��  1Ϊ��С�û�Ȩ��  2Ϊ��С����ԱȨ��
	unsigned short  m_WritePriv;      //дȨ��: 0Ϊ��С����Ȩ��  1Ϊ��С�û�Ȩ��  2Ϊ��С����ԱȨ��

} DATA_LIC;

//�����ļ��������ݽṹ
typedef struct
{
	unsigned long   m_Size;      //�����ļ�����
	DATA_LIC        m_Lic;       //��Ȩ

} DATA_FILE_ATTR;

//˽Կ�ļ���Ȩ�ṹ
typedef struct
{
	long           m_Count;      //�ɵ�����: 0xFFFFFFFF��ʾ������, �ݼ���0��ʾ�Ѳ��ɵ���
	unsigned char  m_Priv;       //����Ȩ��: 0Ϊ��С����Ȩ��  1Ϊ��С�û�Ȩ��  2Ϊ��С����ԱȨ��
	unsigned char  m_IsDecOnRAM; //�Ƿ������ڴ��еݼ�: 1Ϊ���ڴ��еݼ�    0Ϊ��FLASH�еݼ�   
	unsigned char  m_IsReset;    //�û�̬���ú��Ƿ��Զ��ص�����̬: 1Ϊ����ص�����̬ (����Ա̬���ܴ�����)
	unsigned char  m_Reserve;    //����,����4�ֽڶ���

} PRIKEY_LIC;

//��Կ�ļ���Ȩ�ṹ
typedef struct
{
	unsigned long  m_Priv_Enc;   //���ܵ���Ȩ��: 0Ϊ��С����Ȩ��  1Ϊ��С�û�Ȩ��  2Ϊ��С����ԱȨ��

} KEY_LIC;

//SM2��ECC��RSA˽Կ�ļ��������ݽṹ
typedef struct
{
	unsigned short  m_Type;       //��������:ECC˽Կ �� RSA˽Կ
	unsigned short  m_Size;       //���ݳ���:��rsa��˵��1024λ��2048λ, ��ecc��˵��192λ��256λ, ��SM2��˵��256λ
	PRIKEY_LIC      m_Lic;        //��Ȩ

} PRIKEY_FILE_ATTR;

//SM4��TDES��Կ�ļ��������ݽṹ
typedef struct
{
	unsigned long  m_Size;       //��Կ���ݳ���,������16
	KEY_LIC     m_Lic;           //��Ȩ

} KEY_FILE_ATTR;

//�ⲿRSA��Կ��ʽ(����1024,2048)
typedef struct {
	unsigned int  bits;                   // length in bits of modulus
	unsigned int  modulus;                // modulus
	unsigned char exponent[256];          // public exponent
} RSA_PUBLIC_KEY;
	
//�ⲿRSA˽Կ��ʽ(����1024,2048)
typedef struct {
	unsigned int  bits;                   // length in bits of modulus
	unsigned int  modulus;                // modulus
	unsigned char publicExponent[256];    // public exponent
	unsigned char exponent[256];          // private exponent
} RSA_PRIVATE_KEY;

//�ⲿECC\SM2��Կ��ʽ
typedef struct {
	unsigned int bits;
	unsigned int XCoordinate[8];
	unsigned int YCoordinate[8];
}ECCSM2_PUBLIC_KEY;

//�ⲿECCSM2˽Կ��ʽ
typedef struct {
	unsigned int bits;
	unsigned int PrivateKey[8];
} ECCSM2_PRIVATE_KEY;

//ECCSM2��˽Կ�Ը�ʽ
typedef struct {
    ECCSM2_PRIVATE_KEY Prikey;
	ECCSM2_PUBLIC_KEY  Pubkey;
} ECCSM2_KEY_PAIR;

//=======================================================
//�����ļ�
extern WORD  create_file(WORD type, WORD  fileid, BYTE* pattr, int len_attr);
//��ȡ�����ļ�,��fileid=0xFFFFʱ��ʾ��ȡ8K������
extern WORD  read_file(WORD fileid, WORD offset, WORD len, BYTE* pbuf);
//д�ļ�
extern WORD  write_file(WORD type, WORD fileid, WORD offset, WORD len, BYTE* pbuf);
//ɾ���ļ�
extern WORD  delete_file(WORD type, WORD fileid);
//ȡKEY����Ϣ
extern WORD  get_keyinfo(DONGLE_INFO * pKI);
//ȡ��ǰPIN���Ȩ��״̬
extern WORD  get_pinstate(DWORD * pState);
//LED�ƵĿ���
extern WORD  led_control(BYTE flag);
//ȡ�����
extern WORD  get_random(BYTE* pbuf, BYTE len);
//ȡ�����ϵ�ʱ��,��λ��ms,������100ms
extern WORD  get_tickcount(DWORD * pCount);
//ȡʵʱ�ӵ�ʱ��
extern WORD  get_realtime(DWORD * pTime);
//ȡʱ�����ĵ���ʱ��
extern WORD  get_expiretime(DWORD * pTime);
//�������ڴ�(32�ֽڳ�)
extern WORD  get_sharememory(BYTE * pbuf);
//д�����ڴ�(32�ֽڳ�)
extern WORD  set_sharememory(BYTE * pbuf);
//rsa������˽Կ��
extern WORD  rsa_genkey(WORD fileid, RSA_PRIVATE_KEY * pRPK);
//rsa˽Կ�ӽ�������
extern WORD  rsa_pri(WORD fileid, BYTE * pIn, WORD len, BYTE * pOut, WORD * plen_Out, WORD mode);
//rsa��Կ�ӽ�������
extern WORD  rsa_pub(BYTE * pIn, WORD len, RSA_PUBLIC_KEY * pPub, BYTE * pOut, WORD * plen_Out, WORD mode);
//ecc������˽Կ��
extern WORD  ecc_genkey(WORD fileid, ECCSM2_KEY_PAIR * pEKP);
//ecc˽Կ�ӽ�������
extern WORD  ecc_sign(WORD fileid, BYTE * pIn, WORD len, BYTE * pOut, WORD * plen_Out);
//ecc��Կ�ӽ�������
extern WORD  ecc_verify(ECCSM2_PUBLIC_KEY * pEPK, BYTE * pHash, WORD len_Hash, BYTE * pSign);
//sm2������˽Կ��
extern WORD  sm2_genkey(WORD fileid, ECCSM2_KEY_PAIR * pEKP);
//sm2˽Կ�ӽ�������
extern WORD  sm2_sign(WORD fileid, BYTE * pIn, WORD len, BYTE * pOut, WORD * plen_Out);
//sm2��Կ�ӽ�������
extern WORD  sm2_verify(ECCSM2_PUBLIC_KEY * pEPK, BYTE * pHash, WORD len_Hash, BYTE * pSign);
//TDES�ӽ�������
extern WORD  tdes(BYTE * pdata ,int len, int mode, WORD fileid);
//SM4�ӽ�������
extern WORD  sm4(BYTE * pdata ,int len, int mode, WORD fileid);
//sha1��hash����
extern WORD  sha1(BYTE * pdata ,int len, BYTE * phash);
//sm3��hash����
extern WORD  sm3(BYTE * pdata ,int len, BYTE * phash);
//seed����������
extern WORD  seed(BYTE * pseed ,int len, BYTE * presult);

#endif
