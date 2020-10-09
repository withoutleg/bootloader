#include "stm32f10x.h"
#include "aes.h"

//vu8 data[]="80060020891100089111000893110008951100089711000899110008000000000000000000000000000000009B1100089D110008000000009F110008A1110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A3110008A311000800F002F800F03AF80AA090E8000C82448344AAF10107DA4501D100F02FF8AFF2090EBAE80F0013F0010F18BFFB1A43F0010318475403000074030000103A24BF78C878C1FAD8520724BF30C830C144BF04680C60704700000023002400250026103A28BF78C1FBD8520728BF30C148BF0B6070471FB51FBD10B510BD00F031F81146FFF7F7FF00F033F900F04FF803B4FFF7F2FF03BC00F057F800000948804709480047FEE7FEE7FEE7FEE7FEE7FEE7FEE7FEE7FEE7FEE704480549054A064B704700002D130008ED10000880000020800600208002002080020020704770477047754600F02CF8AE4605006946534620F00700854618B020B5FFF7DDFFBDE820404FF000064FF000074FF000084FF0000B21F00701AC46ACE8C009ACE8C009ACE8C009ACE8C0098D46704710B50446AFF300802046BDE81040FFF7A8BF0000004870472000002001491820ABBEFEE726000200704710B500F002F810BD00000CB50020019000903348006840F480303149086000BF3048006800F4003000900198401C0190009818B90198B0F5A06FF1D12948006800F4003010B10120009001E0002000900098012843D12348006840F01000214908600846006820F0030008600846006840F0020008601A484068194948600846406848600846406840F4806048600846406820F47C1048600846406840F4E81048600846006840F08070086000BF0C48006800F000700028F9D00948406820F00300074948600846406840F00200486000BF0348406800F00C000828F9D10CBD0000001002400020024010B51248006840F0010010490860084640680F4908400D494860084600680D4908400A4908600846006820F4802008600846406820F4FE0048604FF41F008860FFF769FF04480549086010BD001002400000FFF8FFFFF6FE0010000808ED00E0104A12684FF47A73B2FBF3F202FB00F10D4A126842F080720B4B1A6000220B4B5A601A46126842F001021A6000BF074A52688A42FBD3054A126822F00102034B1A6070470C000020FCED00E0001000E00EB51FA207CA0090019102929DF80000401CC0B28DF800009DF8000010B976208DF8000019480078401C184908700846007808B9562008701548806940F00400134988611348006820F44040114908600846006840F48050086010E008200D49103108604FF47A70FFF7A2FF4FF400200849103108604FF47A70FFF799FFEDE777777777777777777777000000000020001002400008014094140008000000202000000028110008B414000820000020600600004411000866666666666666666666000000A24A0400000000000000000102030406070809";

 uint8_t AES_key[] = {0x22,0xf2,0xeb,0x79,0xe4,0x62,0x33,0x74,0x94,0xcd,0xfb,0x74,0x2d,0xa6,0x19,0x3e,
											0x5e,0x2e,0x23,0x74,0x70,0x4e,0xc4,0xd3,0x37,0xd9,0x1d,0x98,0xd2,0x2b,0x0c,0xdb};
u8 sbox_table[256];
u8 rsbox_table[256];
		
#define FLASH_PAGE_SIZE 			(u32)1024
#define FLASH_PAGE_AMOUNT			(u32)64
#define BLOCK_SIZE_BYTE 			(u32)(4 + FLASH_PAGE_SIZE + 4) // number_block + data (multiple by 16 bytes) + crc32
#define BLOCK_SIZE_DWORD 			(u32)(BLOCK_SIZE_BYTE / 4)

#define UART_ACK 							(u32)0xA0A0A0A0
#define UART_NACK 						(u32)0x0A0A0A0A
#define UART_MASK_ERR 				(USART_SR_PE | USART_SR_FE | USART_SR_NE | USART_SR_ORE)
#define UART_RECV_ERR_TIMEOUT (u8)0b10000000

// pointer to the setting of external app
#define PROGRAM_ADDR		 			(u32)0x08001000
#define PROGRAM_ADDR_SETTING	(u32)(FLASH_BASE + FLASH_PAGE_AMOUNT * FLASH_PAGE_SIZE - FLASH_PAGE_SIZE)

#define DWT_CYCCNT						*(vu32*)0xE0001004
#define DWT_CONTROL						*(vu32*)0xE0001000
#define SCB_DEMCR							*(vu32*)0xE000EDFC

// количество тактов 
#define	TIMER_50000MS					(u32)(SystemCoreClock * 50)
#define	TIMER_5000MS					(u32)(SystemCoreClock * 5)

#define	TIMEOUT_HELLO					TIMER_50000MS
#define	TIMEOUT_BLOCK					TIMER_5000MS // t = (8 * byte * (d + 1 + s + p)) / (d * V_uart). (8 * 1 * (8 + 1 + 1 + 0)) / (8 * 9600) = minimun ~1sec for UART

vu32 recv_buf[BLOCK_SIZE_DWORD];

void start_DWT()
{
 //разрешаем использовать счётчик
 SCB_DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
 //обнуляем значение счётного регистра
 DWT_CYCCNT  = 0;
 //запускаем счётчик
 DWT_CONTROL|= DWT_CTRL_CYCCNTENA_Msk;
}

#define stop_DWT (DWT_CONTROL &= ~DWT_CTRL_CYCCNTENA_Msk);

void delay_ms(u32 ms)
{
 start_DWT();
 int32_t ms_count_tick = ms * (SystemCoreClock/1000); 
 while (DWT_CYCCNT < ms_count_tick);
 stop_DWT;
}	

// size in DWORD
u32 crc32_calc(vuc32 *addr, u32 size)
{
 // reset crc
 CRC->CR = 1;
 for (u32 i = 0; i < size; ++i)
  CRC->DR = addr[i];
 return CRC->DR;
}

void UART_send_bytes(uc8 *buf, u16 size)
{
 u16 i = 0;
 while (size)
 {
  USART1->SR &= ~USART_SR_TC;
  USART1->DR = buf[i];
	--size;
	++i;
  while (! (USART1->SR & USART_SR_TC));
 }
}

u8 UART_recv_bytes(vu8 *buf, u16 size, vuc32 timeout_tick)
{
 // на этом этапе может находится мусор с ошибками, полученный в период, когда данных не ждали
 // очищаем данные об ошибках
 vu32 tmp = USART1->SR;
 buf[0] = USART1->DR;
	
 start_DWT();	
	
 u8 err = 0;
 u16 i = 0;
 while (size && DWT_CYCCNT < timeout_tick)
 {
	u32 status = USART1->SR;
	if (status & USART_SR_RXNE)
	{
	 buf[i] = USART1->DR;
	 --size;
	 ++i;
	}
	err |= (status & (UART_MASK_ERR));
 }
 
 if (size)
	err |= UART_RECV_ERR_TIMEOUT;
 
 stop_DWT;
 
 return err;
}

void system_shutdown()
{
	// убираем питание с нужного пина
	while(1);
}

void wait_flash()
{
 while (!(FLASH->SR & (FLASH_SR_EOP | FLASH_SR_PGERR | FLASH_SR_WRPRTERR)));
 FLASH->SR |= (FLASH_SR_EOP | FLASH_SR_PGERR | FLASH_SR_WRPRTERR);
}

void write_page_to_flash(u32 addr, u8 *buf)
{	
		// разблокируем flash
		FLASH->KEYR = 0x45670123;
		FLASH->KEYR = 0xCDEF89AB;
		
	 // очищаем страницу перед записью
		
		while (FLASH->SR & FLASH_SR_BSY);
		FLASH->SR |= (FLASH_SR_EOP | FLASH_SR_PGERR | FLASH_SR_WRPRTERR);
			
		FLASH->CR |= FLASH_CR_PER; // указываем на операцию очистки flash
		// указываем адрес страницы
		FLASH->AR = addr;
		// стираем
		FLASH->CR |= FLASH_CR_STRT;
		wait_flash();
		FLASH->CR &= ~FLASH_CR_PER;
	
		// записываем данные

		FLASH->CR |= FLASH_CR_PG; // указываем на операцию записи во flash
		vu16 *p_addr = (u16*)addr;
		u16* p_buf = (u16*)buf;
		for (u32 i = 0; i < FLASH_PAGE_SIZE / 2; ++i)
		{
		 *p_addr = *p_buf;
		 ++p_addr;
		 ++p_buf;
			
     wait_flash();
		}
		FLASH->CR &= ~FLASH_CR_PG;
		
		// блокируем flash
		FLASH->CR |= FLASH_CR_LOCK;
}

 // на телефоне выбираем перепрошить. телефон отправляет команду основной программе. 
 // программа ставит в SETTING байт NEED_BOOT и делает программный reset
 // bluetooth на этот момент запущен и настроен основной программой
 // настроить bluetooth (если основная программа использует иные настройки скорости и прочего)
 
	 // процедура перепрошивки
	 // принимаем стартовое сообщение crc32_firmware, которое говорит о начале приема данных. в конце каждого сообщения дописываем CRC32
	 // принимаем данные блоками (BLOCK_NUMBER+1024 зашифрованных байта). дешифруем и записываем страницу во flash и т.д.
	 // клиент - mcu, сервер - phone
	 
	 // сервер: crc32_firmware
	 // клиент: ACK
	 // сервер: отправить block (ждем ответа по timeout_block*2 * 3 + время на запись во flash). timeout_block? ошибка соединения, отключиться
	 // клиент: принять block в течении timeout_block. если timeout_block или !crc, то NACK, иначе ACK (всего может быть 3 ошибки передачи подряд)
	 // сервер: NACK ? отправить block еще раз, иначе следующий block. если отправляем последний block, то BLOCK_NUMBER |= 0b10000000
	 // ...
	 // сервер: последний block содержит BLOCK_NUMBER у которого установлен старший бит
	 // клиент: ACK	

int main(void)
{		
 // если условие перепрошивки не будет выполнено, то нужно сбросить всю периферию, которой касались перед входом в основную программу
 // enable clock to AHB_CRC
 RCC->AHBENR |= RCC_AHBENR_CRCEN;

 // если питания на bluetooth не было, а нам нужно его настроить, то нужно дождаться пока он стартанет
 // delay_ms(200);
	
 struct s_program_setting
 {
  u32 crc32_firmware;
  u16 size_firmware; // in flash pages
  u8 is_need_boot;
 };
 struct s_program_setting *program_setting;
 program_setting = (struct s_program_setting*)PROGRAM_ADDR_SETTING;
 
 if (program_setting->size_firmware > FLASH_PAGE_AMOUNT || 
	   crc32_calc((u32*)PROGRAM_ADDR, program_setting->size_firmware * (FLASH_PAGE_SIZE >> 2)) != program_setting->crc32_firmware ||
	   program_setting->is_need_boot)
 {
	u32 crc32_firmware_new;
	 
  // настраиваем GPIO для USART1
  RCC->APB2ENR |= (RCC_APB2ENR_IOPAEN | RCC_APB2ENR_AFIOEN); 	// GPIOA Clock ON. Alter function clock ON
  GPIOA->CRH &= ~GPIO_CRH_CNF9; 				// Clear CNF bit 9
  GPIOA->CRH	|= GPIO_CRH_CNF9_1;				// Set CNF bit 9 to 10 - AFIO Push-Pull
  GPIOA->CRH	|= GPIO_CRH_MODE9_0;			// Set MODE bit 9 to Mode 01 = 10MHz
	
  GPIOA->CRH	&= ~GPIO_CRH_CNF10;			// Clear CNF bit 9
  GPIOA->CRH	|= GPIO_CRH_CNF10_0;		// Set CNF bit 9 to 01 = HiZ
  GPIOA->CRH	&= ~GPIO_CRH_MODE10;		// Set MODE bit 9 to Mode 01 = 10MHz

  // включаем тактирование для USART1
  RCC->APB2ENR |= RCC_APB2ENR_USART1EN;
  // устанавливаем бодрейт в зависимости от частоты шины, на которой находится UARTx
  // BRR=(freq+baudrate/2)/baudrate
  USART1->BRR = 0x00001D4C;
 
  // включаем USART1, разрешаем прием и передачу
  USART1->CR1 |= USART_CR1_UE | USART_CR1_TE | USART_CR1_RE;
	
	u8 is_break_boot = 0;
	u8 count_follow_err = 0; // количество ошибок приема подряд
	// ждем стартовое сообщение в течении 50 сек
  while (! is_break_boot)	
	{
	 u8 err = UART_recv_bytes((u8*)recv_buf, 8, TIMER_50000MS);
	 if (err || crc32_calc(recv_buf, 1)  != recv_buf[1])
	 {
	  // если 3 ошибки подряд, завершаем прошивку
		if (count_follow_err >= 2)
		 is_break_boot = 1;
		++count_follow_err;
		continue;
	 }

	 count_follow_err = 0;
	 // если приняли CRC32_FIRMWARE, то отвечаем ACK и ждем данные прошивки
	 crc32_firmware_new = recv_buf[0];
	 recv_buf[0] = UART_ACK;
	 recv_buf[1] = crc32_calc(recv_buf, 1);
	 UART_send_bytes((u8*)recv_buf, 8);
	 break;
	}
	
	u32 i_page = 0;
	u8 is_last_page = 0;
  struct AES_ctx ctx;
  ctx.p_sBoxTable = sbox_table;
  ctx.p_rsBoxTable = rsbox_table;
  AES_init_ctx(&ctx, AES_key);
	// принимаем блоки данных
	while (! is_break_boot && ! is_last_page)
	{
	 u8 err = UART_recv_bytes((u8*)recv_buf, BLOCK_SIZE_BYTE, TIMEOUT_BLOCK);
		
	 if (err || crc32_calc(recv_buf, BLOCK_SIZE_DWORD - 1) != recv_buf[BLOCK_SIZE_DWORD - 1])
	 {
		 // если 3 ошибки подряд, завершаем прошивку
		if (count_follow_err >= 2)
		 is_break_boot = 1;
		++count_follow_err;
	  recv_buf[0] = UART_NACK;
	  recv_buf[1] = crc32_calc(recv_buf, 1);
	  UART_send_bytes((u8*)recv_buf, 8);
		continue;
	 }
	 count_follow_err = 0;
	 
	 // расшифровываем
	 u8 *p_AES_data = (u8*)(recv_buf + 1);
	 for (vu32 i = 0; i < BLOCK_SIZE_BYTE - 8; i += 16)
	 {
    AES_ECB_decrypt(&ctx, &p_AES_data[i]);
		vu32 tmp = 0;
	 }
	 
	 // записываем во flash
	 i_page = *recv_buf; // страница, в которую нужно записать блок

	 // если старший бит установлен, то это последний блок
	 if (i_page & 0x80000000)
	 {
		i_page &= 0x7FFFFFFF;
		is_last_page = 1;
	 }
	 
	 write_page_to_flash(PROGRAM_ADDR + (FLASH_PAGE_SIZE * i_page), p_AES_data);
	 
	 // отправляем ACK
	 recv_buf[0] = UART_ACK;
	 recv_buf[1] = crc32_calc(recv_buf, 1);
	 UART_send_bytes((u8*)recv_buf, 8);
	}
	
	// записываем crc32_firmware, размер прошивки (в PAGE_SIZE) и is_need_boot = 0 в setting
	if (! is_break_boot)
	{
	 // сохранить страницу, стереть, записать
	 for (u16 i = 0; i < (FLASH_PAGE_SIZE >> 2); ++i)
		recv_buf[i] = ((vu32*)PROGRAM_ADDR_SETTING)[i];
	 *recv_buf = crc32_firmware_new;
	 ((u16*)recv_buf)[2] = (u16)(i_page + 1);
	 ((u8*)recv_buf)[6] = 0;
	 write_page_to_flash(PROGRAM_ADDR_SETTING, (u8*)recv_buf);
	 NVIC_SystemReset(); // ножка RST МК не должна быть подтянута к V
	}else
	 system_shutdown();
 }
 
 // disable clock to AHB_CRC
 RCC->AHBENR &= ~RCC_AHBENR_CRCEN;
 
 // jump to the main app
 u32 app_jump_address;
 typedef void(*pFunction)(void);
 pFunction Jump_To_Application;
// __disable_irq();
 app_jump_address = *(u32*) (PROGRAM_ADDR + 4); // second word is RESET pointer
 Jump_To_Application = (pFunction)app_jump_address;
 __set_MSP(*(vu32*) PROGRAM_ADDR); // first word is top of stack
 // supposed to vector table reset in main app (by SystemInit())
 Jump_To_Application();
}
