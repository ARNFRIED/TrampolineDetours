#pragma once
#include "Opcodes.h"
#include "Log.hpp"

using uint64 = unsigned long long;
using QWORD = unsigned long long;
using DWORD = unsigned long;
using uint16 = unsigned short;
using byte = unsigned char;

//-------------------------------------------------------------------------------------------------------
//--------------------------- S T R U C T U R E S -------------------------------------------------------
//-------------------------------------------------------------------------------------------------------
#pragma pack(1)

struct CurMgr
{
	int field00; //0x00
	int field04; //0x04
	int field08; //0x08
	int field0C; //0x0C
	int field10; //0x10
	int field14; //0x14
	int field18; //0x18
	int field1C; //0x1C
	int field20; //0x20
	int field24; //0x24
	int field28; //0x28
	int field2C; //0x2C
	int field30; //0x30
	int field34; //0x34
	int field38; //0x38
	int field3C; //0x3C
	int field40; //0x40
	int field44; //0x44
	int field48; //0x48
	int field4C; //0x4C
	int field50; //0x50
	int field54; //0x54
	int field58; //0x58
	int field5C; //0x5C
	int field60; //0x60
	int field64; //0x64
	int field68; //0x68
	int field6C; //0x6C
	int field70; //0x70
	int field74; //0x74
	int field78; //0x78
	int field7C; //0x7C
	int field80; //0x80
	int field84; //0x84
	int field88; //0x88
	int field8C; //0x8C
	int field90; //0x90
	int field94; //0x94
	int field98; //0x98
	int field9C; //0x9C
	int fieldA0; //0xA0
	int nextObj; // 0xA4
	int fieldA8; // 0xA8
	int firstObj; // 0xAC
	int fieldB0; //0xB0
	int fieldB4; //0xB4
	int fieldB8; //0xB8
	int fieldBC; //0xBC
	uint64 activePlayer; //0xC0
	int fieldC8; //0xC8
	int mapId; //0xCC
	int fieldD0; //0xD0
	int movementGlobals; //0xD4
	int fieldD8; //0xD8
	int fieldDC; //0xDC
};

struct BaseObject
{
	int vtable;  //0x00
	int field04; //0x04
	int field08; //0x08
	int field0C; //0x0C
	int field10; //0x10
	int type;	 //0x14
	int field18; //0x18
	int field1C; //0x1C
	int field20; //0x20
	int field24; //0x24
	int field28; //0x28
	int field2C; //0x2C
	uint64 guid; //0x30
};

//---------------------------------		D E S C R I P T O R S		------------------------------

struct ItemEnchantment
{
	int Id;
	int Duration;
	int Charges;
};

struct ObjectFields
{
	QWORD OBJECT_FIELD_GUID;                                // 0x00000000
	DWORD OBJECT_FIELD_TYPE;                                // 0x00000008
	DWORD OBJECT_FIELD_ENTRY;                               // 0x0000000C
	DWORD OBJECT_FIELD_SCALE_X;                             // 0x00000010
	DWORD OBJECT_FIELD_PADDING;                             // 0x00000014
};

struct ItemFields
{
	ObjectFields objectFields;
	QWORD ITEM_FIELD_OWNER;                                 // 0x00000018
	QWORD ITEM_FIELD_CONTAINED;                             // 0x00000020
	QWORD ITEM_FIELD_CREATOR;                               // 0x00000028
	QWORD ITEM_FIELD_GIFTCREATOR;                           // 0x00000030
	DWORD ITEM_FIELD_STACK_COUNT;                           // 0x00000038
	DWORD ITEM_FIELD_DURATION;                              // 0x0000003C
	DWORD ITEM_FIELD_SPELL_CHARGES[5];                      // 0x00000040
	DWORD ITEM_FIELD_FLAGS;                                 // 0x00000054
	ItemEnchantment PERM_ENCHANTMENT_SLOT;                  // 0x00000058
	ItemEnchantment TEMP_ENCHANTMENT_SLOT;                  // 0x00000064
	ItemEnchantment MAX_INSPECTED_ENCHANTMENT_SLOT;         // 0x00000070
	ItemEnchantment PROP_ENCHANTMENT_SLOT_0;                // 0x0000007C
	ItemEnchantment PROP_ENCHANTMENT_SLOT_1;                // 0x00000088
	ItemEnchantment PROP_ENCHANTMENT_SLOT_2;                // 0x00000094
	ItemEnchantment PROP_ENCHANTMENT_SLOT_3;                // 0x000000A0
	DWORD ITEM_FIELD_PROPERTY_SEED;                         // 0x000000AC
	DWORD ITEM_FIELD_RANDOM_PROPERTIES_ID;                  // 0x000000B0
	DWORD ITEM_FIELD_ITEM_TEXT_ID;                          // 0x000000B4
	DWORD ITEM_FIELD_DURABILITY;                            // 0x000000B8
	DWORD ITEM_FIELD_MAXDURABILITY;                         // 0x000000BC
};

struct ContainerFields
{
	ItemFields itemFields;
	DWORD CONTAINER_FIELD_NUM_SLOTS;                        // 0x000000C0
	DWORD CONTAINER_ALIGN_PAD;                              // 0x000000C4
	DWORD CONTAINER_FIELD_SLOT_1[72];                       // 0x000000C8
};

struct UnitFields
{
	ObjectFields objectFields;
	QWORD UNIT_FIELD_CHARM;                                 // 0x00000018
	QWORD UNIT_FIELD_SUMMON;                                // 0x00000020
	QWORD UNIT_FIELD_CHARMEDBY;                             // 0x00000028
	QWORD UNIT_FIELD_SUMMONEDBY;                            // 0x00000030
	QWORD UNIT_FIELD_CREATEDBY;                             // 0x00000038
	QWORD UNIT_FIELD_TARGET;                                // 0x00000040
	QWORD UNIT_FIELD_PERSUADED;                             // 0x00000048
	QWORD UNIT_FIELD_CHANNEL_OBJECT;                        // 0x00000050
	DWORD UNIT_FIELD_HEALTH;                                // 0x00000058
	DWORD UNIT_FIELD_POWER1;                                // 0x0000005C
	DWORD UNIT_FIELD_POWER2;                                // 0x00000060
	DWORD UNIT_FIELD_POWER3;                                // 0x00000064
	DWORD UNIT_FIELD_POWER4;                                // 0x00000068
	DWORD UNIT_FIELD_POWER5;                                // 0x0000006C
	DWORD UNIT_FIELD_MAXHEALTH;                             // 0x00000070
	DWORD UNIT_FIELD_MAXPOWER1;                             // 0x00000074
	DWORD UNIT_FIELD_MAXPOWER2;                             // 0x00000078
	DWORD UNIT_FIELD_MAXPOWER3;                             // 0x0000007C
	DWORD UNIT_FIELD_MAXPOWER4;                             // 0x00000080
	DWORD UNIT_FIELD_MAXPOWER5;                             // 0x00000084
	DWORD UNIT_FIELD_LEVEL;                                 // 0x00000088
	DWORD UNIT_FIELD_FACTIONTEMPLATE;                       // 0x0000008C
	byte  UNIT_FIELD_RACE;                                  // 0x00000090
	byte  UNIT_FIELD_CLASS;                                 // 0x00000091
	byte  UNIT_FIELD_GENDER;                                // 0x00000092
	byte  UNIT_FIELD_POWER_TYPE;                            // 0x00000093
	DWORD UNIT_VIRTUAL_ITEM_SLOT_DISPLAY[3];                // 0x00000094
	DWORD UNIT_VIRTUAL_ITEM_INFO[6];                        // 0x000000A0
	DWORD UNIT_FIELD_FLAGS;                                 // 0x000000B8
	DWORD UNIT_FIELD_AURA[48];                              // 0x000000BC
	DWORD UNIT_FIELD_AURAFLAGS[6];                          // 0x0000017C
	DWORD UNIT_FIELD_AURALEVELS[12];                        // 0x00000194
	DWORD UNIT_FIELD_AURAAPPLICATIONS[12];                  // 0x000001C4
	DWORD UNIT_FIELD_AURASTATE;                             // 0x000001F4
	QWORD UNIT_FIELD_BASEATTACKTIME;                        // 0x000001F8
	DWORD UNIT_FIELD_RANGEDATTACKTIME;                      // 0x00000200
	DWORD UNIT_FIELD_BOUNDINGRADIUS;                        // 0x00000204
	DWORD UNIT_FIELD_COMBATREACH;                           // 0x00000208
	DWORD UNIT_FIELD_DISPLAYID;                             // 0x0000020C
	DWORD UNIT_FIELD_NATIVEDISPLAYID;                       // 0x00000210
	DWORD UNIT_FIELD_MOUNTDISPLAYID;                        // 0x00000214
	DWORD UNIT_FIELD_MINDAMAGE;                             // 0x00000218
	DWORD UNIT_FIELD_MAXDAMAGE;                             // 0x0000021C
	DWORD UNIT_FIELD_MINOFFHANDDAMAGE;                      // 0x00000220
	DWORD UNIT_FIELD_MAXOFFHANDDAMAGE;                      // 0x00000224
	byte  UNIT_FIELD_BYTES_1[4];                            // 0x00000228
	DWORD UNIT_FIELD_PETNUMBER;                             // 0x0000022C
	DWORD UNIT_FIELD_PET_NAME_TIMESTAMP;                    // 0x00000230
	DWORD UNIT_FIELD_PETEXPERIENCE;                         // 0x00000234
	DWORD UNIT_FIELD_PETNEXTLEVELEXP;                       // 0x00000238
	DWORD UNIT_DYNAMIC_FLAGS;                               // 0x0000023C
	DWORD UNIT_CHANNEL_SPELL;                               // 0x00000240
	DWORD UNIT_MOD_CAST_SPEED;                              // 0x00000244
	DWORD UNIT_CREATED_BY_SPELL;                            // 0x00000248
	DWORD UNIT_NPC_FLAGS;                                   // 0x0000024C
	DWORD UNIT_NPC_EMOTESTATE;                              // 0x00000250
	DWORD UNIT_TRAINING_POINTS;                             // 0x00000254
	DWORD UNIT_FIELD_STAT0;                                 // 0x00000258
	DWORD UNIT_FIELD_STAT1;                                 // 0x0000025C
	DWORD UNIT_FIELD_STAT2;                                 // 0x00000260
	DWORD UNIT_FIELD_STAT3;                                 // 0x00000264
	DWORD UNIT_FIELD_STAT4;                                 // 0x00000268
	DWORD UNIT_FIELD_RESISTANCES[7];                        // 0x0000026C
	DWORD UNIT_FIELD_BASE_MANA;                             // 0x00000288
	DWORD UNIT_FIELD_BASE_HEALTH;                           // 0x0000028C
	byte  UNIT_FIELD_BYTES_2[4];                            // 0x00000290
	DWORD UNIT_FIELD_ATTACK_POWER;                          // 0x00000294
	DWORD UNIT_FIELD_ATTACK_POWER_MODS;                     // 0x00000298
	DWORD UNIT_FIELD_ATTACK_POWER_MULTIPLIER;               // 0x0000029C
	DWORD UNIT_FIELD_RANGED_ATTACK_POWER;                   // 0x000002A0
	DWORD UNIT_FIELD_RANGED_ATTACK_POWER_MODS;              // 0x000002A4
	DWORD UNIT_FIELD_RANGED_ATTACK_POWER_MULTIPLIER;        // 0x000002A8
	DWORD UNIT_FIELD_MINRANGEDDAMAGE;                       // 0x000002AC
	DWORD UNIT_FIELD_MAXRANGEDDAMAGE;                       // 0x000002B0
	DWORD UNIT_FIELD_POWER_COST_MODIFIER[7];                // 0x000002B4
	DWORD UNIT_FIELD_POWER_COST_MULTIPLIER[7];              // 0x000002D0
	DWORD UNIT_FIELD_PADDING;                               // 0x000002EC
};

auto ufz = sizeof(UnitFields);	//752

struct PlayerFields
{
	UnitFields unitFields;
	QWORD PLAYER_DUEL_ARBITER;                              // 0x000002F0
	DWORD PLAYER_FLAGS;                                     // 0x000002F8
	DWORD PLAYER_GUILDID;                                   // 0x000002FC
	DWORD PLAYER_GUILDRANK;                                 // 0x00000300
	byte PLAYER_BYTES[4];                                   // 0x00000304
	byte PLAYER_BYTES_2[4];                                 // 0x00000308
	byte PLAYER_BYTES_3[4];                                 // 0x0000030C
	DWORD PLAYER_DUEL_TEAM;                                 // 0x00000310
	DWORD PLAYER_GUILD_TIMESTAMP;                           // 0x00000314
	DWORD PLAYER_QUEST_LOG_1_1;                             // 0x00000318
	QWORD PLAYER_QUEST_LOG_1_2;                             // 0x0000031C
	DWORD PLAYER_QUEST_LOG_2_1;                             // 0x00000324
	QWORD PLAYER_QUEST_LOG_2_2;                             // 0x00000328
	DWORD PLAYER_QUEST_LOG_3_1;                             // 0x00000330
	QWORD PLAYER_QUEST_LOG_3_2;                             // 0x00000334
	DWORD PLAYER_QUEST_LOG_4_1;                             // 0x0000033C
	QWORD PLAYER_QUEST_LOG_4_2;                             // 0x00000340
	DWORD PLAYER_QUEST_LOG_5_1;                             // 0x00000348
	QWORD PLAYER_QUEST_LOG_5_2;                             // 0x0000034C
	DWORD PLAYER_QUEST_LOG_6_1;                             // 0x00000354
	QWORD PLAYER_QUEST_LOG_6_2;                             // 0x00000358
	DWORD PLAYER_QUEST_LOG_7_1;                             // 0x00000360
	QWORD PLAYER_QUEST_LOG_7_2;                             // 0x00000364
	DWORD PLAYER_QUEST_LOG_8_1;                             // 0x0000036C
	QWORD PLAYER_QUEST_LOG_8_2;                             // 0x00000370
	DWORD PLAYER_QUEST_LOG_9_1;                             // 0x00000378
	QWORD PLAYER_QUEST_LOG_9_2;                             // 0x0000037C
	DWORD PLAYER_QUEST_LOG_10_1;                            // 0x00000384
	QWORD PLAYER_QUEST_LOG_10_2;                            // 0x00000388
	DWORD PLAYER_QUEST_LOG_11_1;                            // 0x00000390
	QWORD PLAYER_QUEST_LOG_11_2;                            // 0x00000394
	DWORD PLAYER_QUEST_LOG_12_1;                            // 0x0000039C
	QWORD PLAYER_QUEST_LOG_12_2;                            // 0x000003A0
	DWORD PLAYER_QUEST_LOG_13_1;                            // 0x000003A8
	QWORD PLAYER_QUEST_LOG_13_2;                            // 0x000003AC
	DWORD PLAYER_QUEST_LOG_14_1;                            // 0x000003B4
	QWORD PLAYER_QUEST_LOG_14_2;                            // 0x000003B8
	DWORD PLAYER_QUEST_LOG_15_1;                            // 0x000003C0
	QWORD PLAYER_QUEST_LOG_15_2;                            // 0x000003C4
	DWORD PLAYER_QUEST_LOG_16_1;                            // 0x000003CC
	QWORD PLAYER_QUEST_LOG_16_2;                            // 0x000003D0
	DWORD PLAYER_QUEST_LOG_17_1;                            // 0x000003D8
	QWORD PLAYER_QUEST_LOG_17_2;                            // 0x000003DC
	DWORD PLAYER_QUEST_LOG_18_1;                            // 0x000003E4
	QWORD PLAYER_QUEST_LOG_18_2;                            // 0x000003E8
	DWORD PLAYER_QUEST_LOG_19_1;                            // 0x000003F0
	QWORD PLAYER_QUEST_LOG_19_2;                            // 0x000003F4
	DWORD PLAYER_QUEST_LOG_20_1;                            // 0x000003FC
	QWORD PLAYER_QUEST_LOG_20_2;                            // 0x00000400
	QWORD PLAYER_VISIBLE_ITEM_1_CREATOR;                    // 0x00000408
	DWORD PLAYER_VISIBLE_ITEM_1_0[8];                       // 0x00000410
	DWORD PLAYER_VISIBLE_ITEM_1_PROPERTIES;                 // 0x00000430
	DWORD PLAYER_VISIBLE_ITEM_1_PAD;                        // 0x00000434
	QWORD PLAYER_VISIBLE_ITEM_2_CREATOR;                    // 0x00000438
	DWORD PLAYER_VISIBLE_ITEM_2_0[8];                       // 0x00000440
	DWORD PLAYER_VISIBLE_ITEM_2_PROPERTIES;                 // 0x00000460
	DWORD PLAYER_VISIBLE_ITEM_2_PAD;                        // 0x00000464
	QWORD PLAYER_VISIBLE_ITEM_3_CREATOR;                    // 0x00000468
	DWORD PLAYER_VISIBLE_ITEM_3_0[8];                       // 0x00000470
	DWORD PLAYER_VISIBLE_ITEM_3_PROPERTIES;                 // 0x00000490
	DWORD PLAYER_VISIBLE_ITEM_3_PAD;                        // 0x00000494
	QWORD PLAYER_VISIBLE_ITEM_4_CREATOR;                    // 0x00000498
	DWORD PLAYER_VISIBLE_ITEM_4_0[8];                       // 0x000004A0
	DWORD PLAYER_VISIBLE_ITEM_4_PROPERTIES;                 // 0x000004C0
	DWORD PLAYER_VISIBLE_ITEM_4_PAD;                        // 0x000004C4
	QWORD PLAYER_VISIBLE_ITEM_5_CREATOR;                    // 0x000004C8
	DWORD PLAYER_VISIBLE_ITEM_5_0[8];                       // 0x000004D0
	DWORD PLAYER_VISIBLE_ITEM_5_PROPERTIES;                 // 0x000004F0
	DWORD PLAYER_VISIBLE_ITEM_5_PAD;                        // 0x000004F4
	QWORD PLAYER_VISIBLE_ITEM_6_CREATOR;                    // 0x000004F8
	DWORD PLAYER_VISIBLE_ITEM_6_0[8];                       // 0x00000500
	DWORD PLAYER_VISIBLE_ITEM_6_PROPERTIES;                 // 0x00000520
	DWORD PLAYER_VISIBLE_ITEM_6_PAD;                        // 0x00000524
	QWORD PLAYER_VISIBLE_ITEM_7_CREATOR;                    // 0x00000528
	DWORD PLAYER_VISIBLE_ITEM_7_0[8];                       // 0x00000530
	DWORD PLAYER_VISIBLE_ITEM_7_PROPERTIES;                 // 0x00000550
	DWORD PLAYER_VISIBLE_ITEM_7_PAD;                        // 0x00000554
	QWORD PLAYER_VISIBLE_ITEM_8_CREATOR;                    // 0x00000558
	DWORD PLAYER_VISIBLE_ITEM_8_0[8];                       // 0x00000560
	DWORD PLAYER_VISIBLE_ITEM_8_PROPERTIES;                 // 0x00000580
	DWORD PLAYER_VISIBLE_ITEM_8_PAD;                        // 0x00000584
	QWORD PLAYER_VISIBLE_ITEM_9_CREATOR;                    // 0x00000588
	DWORD PLAYER_VISIBLE_ITEM_9_0[8];                       // 0x00000590
	DWORD PLAYER_VISIBLE_ITEM_9_PROPERTIES;                 // 0x000005B0
	DWORD PLAYER_VISIBLE_ITEM_9_PAD;                        // 0x000005B4
	QWORD PLAYER_VISIBLE_ITEM_10_CREATOR;                   // 0x000005B8
	DWORD PLAYER_VISIBLE_ITEM_10_0[8];                      // 0x000005C0
	DWORD PLAYER_VISIBLE_ITEM_10_PROPERTIES;                // 0x000005E0
	DWORD PLAYER_VISIBLE_ITEM_10_PAD;                       // 0x000005E4
	QWORD PLAYER_VISIBLE_ITEM_11_CREATOR;                   // 0x000005E8
	DWORD PLAYER_VISIBLE_ITEM_11_0[8];                      // 0x000005F0
	DWORD PLAYER_VISIBLE_ITEM_11_PROPERTIES;                // 0x00000610
	DWORD PLAYER_VISIBLE_ITEM_11_PAD;                       // 0x00000614
	QWORD PLAYER_VISIBLE_ITEM_12_CREATOR;                   // 0x00000618
	DWORD PLAYER_VISIBLE_ITEM_12_0[8];                      // 0x00000620
	DWORD PLAYER_VISIBLE_ITEM_12_PROPERTIES;                // 0x00000640
	DWORD PLAYER_VISIBLE_ITEM_12_PAD;                       // 0x00000644
	QWORD PLAYER_VISIBLE_ITEM_13_CREATOR;                   // 0x00000648
	DWORD PLAYER_VISIBLE_ITEM_13_0[8];                      // 0x00000650
	DWORD PLAYER_VISIBLE_ITEM_13_PROPERTIES;                // 0x00000670
	DWORD PLAYER_VISIBLE_ITEM_13_PAD;                       // 0x00000674
	QWORD PLAYER_VISIBLE_ITEM_14_CREATOR;                   // 0x00000678
	DWORD PLAYER_VISIBLE_ITEM_14_0[8];                      // 0x00000680
	DWORD PLAYER_VISIBLE_ITEM_14_PROPERTIES;                // 0x000006A0
	DWORD PLAYER_VISIBLE_ITEM_14_PAD;                       // 0x000006A4
	QWORD PLAYER_VISIBLE_ITEM_15_CREATOR;                   // 0x000006A8
	DWORD PLAYER_VISIBLE_ITEM_15_0[8];                      // 0x000006B0
	DWORD PLAYER_VISIBLE_ITEM_15_PROPERTIES;                // 0x000006D0
	DWORD PLAYER_VISIBLE_ITEM_15_PAD;                       // 0x000006D4
	QWORD PLAYER_VISIBLE_ITEM_16_CREATOR;                   // 0x000006D8
	DWORD PLAYER_VISIBLE_ITEM_16_0[8];                      // 0x000006E0
	DWORD PLAYER_VISIBLE_ITEM_16_PROPERTIES;                // 0x00000700
	DWORD PLAYER_VISIBLE_ITEM_16_PAD;                       // 0x00000704
	QWORD PLAYER_VISIBLE_ITEM_17_CREATOR;                   // 0x00000708
	DWORD PLAYER_VISIBLE_ITEM_17_0[8];                      // 0x00000710
	DWORD PLAYER_VISIBLE_ITEM_17_PROPERTIES;                // 0x00000730
	DWORD PLAYER_VISIBLE_ITEM_17_PAD;                       // 0x00000734
	QWORD PLAYER_VISIBLE_ITEM_18_CREATOR;                   // 0x00000738
	DWORD PLAYER_VISIBLE_ITEM_18_0[8];                      // 0x00000740
	DWORD PLAYER_VISIBLE_ITEM_18_PROPERTIES;                // 0x00000760
	DWORD PLAYER_VISIBLE_ITEM_18_PAD;                       // 0x00000764
	QWORD PLAYER_VISIBLE_ITEM_19_CREATOR;                   // 0x00000768
	DWORD PLAYER_VISIBLE_ITEM_19_0[8];                      // 0x00000770
	DWORD PLAYER_VISIBLE_ITEM_19_PROPERTIES;                // 0x00000790
	DWORD PLAYER_VISIBLE_ITEM_19_PAD;                       // 0x00000794
	QWORD PLAYER_FIELD_INV_SLOT_HEAD[23];                   // 0x00000798
	//QWORD PLAYER_FIELD_INV_SLOT_NECK;                     // 0x000007A0
	//QWORD PLAYER_FIELD_INV_SLOT_SHOULDER;                 // 0x000007A8
	//QWORD PLAYER_FIELD_INV_SLOT_SHIRT;                    // 0x000007B0
	//QWORD PLAYER_FIELD_INV_SLOT_CHEST;                    // 0x000007B8
	//QWORD PLAYER_FIELD_INV_SLOT_WAIST;                    // 0x000007C0
	//QWORD PLAYER_FIELD_INV_SLOT_LEGS;                     // 0x000007C8
	//QWORD PLAYER_FIELD_INV_SLOT_FEET;                     // 0x000007D0
	//QWORD PLAYER_FIELD_INV_SLOT_WRIST;                    // 0x000007D8
	//QWORD PLAYER_FIELD_INV_SLOT_HANDS;                    // 0x000007E0
	//QWORD PLAYER_FIELD_INV_SLOT_FINGER1;                  // 0x000007E8
	//QWORD PLAYER_FIELD_INV_SLOT_FINGER2;                  // 0x000007F0
	//QWORD PLAYER_FIELD_INV_SLOT_TRINKET1;                 // 0x000007F8
	//QWORD PLAYER_FIELD_INV_SLOT_TRINKET2;                 // 0x00000800
	//QWORD PLAYER_FIELD_INV_SLOT_BACK;                     // 0x00000808
	//QWORD PLAYER_FIELD_INV_SLOT_MAIN_HAND;                // 0x00000810
	//QWORD PLAYER_FIELD_INV_SLOT_OFF_HAND;                 // 0x00000818
	//QWORD PLAYER_FIELD_INV_SLOT_RANGED;                   // 0x00000820
	//QWORD PLAYER_FIELD_INV_SLOT_TABARD;                   // 0x00000828
	//QWORD PLAYER_FIELD_INV_SLOT_BAG1;                     // 0x00000830
	//QWORD PLAYER_FIELD_INV_SLOT_BAG2;                     // 0x00000838
	//QWORD PLAYER_FIELD_INV_SLOT_BAG3;                     // 0x00000840
	//QWORD PLAYER_FIELD_INV_SLOT_BAG4;                     // 0x00000848
	QWORD PLAYER_FIELD_PACK_SLOT_1[16];                     // 0x00000850
	QWORD PLAYER_FIELD_BANK_SLOT_1[24];                     // 0x000008D0
	QWORD PLAYER_FIELD_BANKBAG_SLOT_1[6];                   // 0x00000990
	QWORD PLAYER_FIELD_VENDORBUYBACK_SLOT_1[12];            // 0x000009C0
	QWORD PLAYER_FIELD_KEYRING_SLOT_1[32];                  // 0x00000A20
	QWORD PLAYER_FARSIGHT;                                  // 0x00000B20
	QWORD PLAYER__FIELD_COMBO_TARGET;                       // 0x00000B28
	DWORD PLAYER_XP;                                        // 0x00000B30
	DWORD PLAYER_NEXT_LEVEL_XP;                             // 0x00000B34
	DWORD PLAYER_SKILL_INFO_1_1[384];                       // 0x00000B38
	DWORD PLAYER_CHARACTER_POINTS1;                         // 0x00001138
	DWORD PLAYER_CHARACTER_POINTS2;                         // 0x0000113C
	DWORD PLAYER_TRACK_CREATURES;                           // 0x00001140
	DWORD PLAYER_TRACK_RESOURCES;                           // 0x00001144
	DWORD PLAYER_BLOCK_PERCENTAGE;                          // 0x00001148
	DWORD PLAYER_DODGE_PERCENTAGE;                          // 0x0000114C
	DWORD PLAYER_PARRY_PERCENTAGE;                          // 0x00001150
	DWORD PLAYER_CRIT_PERCENTAGE;                           // 0x00001154
	DWORD PLAYER_RANGED_CRIT_PERCENTAGE;                    // 0x00001158
	DWORD PLAYER_EXPLORED_ZONES_1[64];                      // 0x0000115C
	DWORD PLAYER_REST_STATE_EXPERIENCE;                     // 0x0000125C
	DWORD PLAYER_FIELD_COINAGE;                             // 0x00001260
	DWORD PLAYER_FIELD_POSSTAT0;                            // 0x00001264
	DWORD PLAYER_FIELD_POSSTAT1;                            // 0x00001268
	DWORD PLAYER_FIELD_POSSTAT2;                            // 0x0000126C
	DWORD PLAYER_FIELD_POSSTAT3;                            // 0x00001270
	DWORD PLAYER_FIELD_POSSTAT4;                            // 0x00001274
	DWORD PLAYER_FIELD_NEGSTAT0;                            // 0x00001278
	DWORD PLAYER_FIELD_NEGSTAT1;                            // 0x0000127C
	DWORD PLAYER_FIELD_NEGSTAT2;                            // 0x00001280
	DWORD PLAYER_FIELD_NEGSTAT3;                            // 0x00001284
	DWORD PLAYER_FIELD_NEGSTAT4;                            // 0x00001288
	DWORD PLAYER_FIELD_RESISTANCEBUFFMODSPOSITIVE[7];       // 0x0000128C
	DWORD PLAYER_FIELD_RESISTANCEBUFFMODSNEGATIVE[7];       // 0x000012A8
	DWORD PLAYER_FIELD_MOD_DAMAGE_DONE_POS[7];              // 0x000012C4
	DWORD PLAYER_FIELD_MOD_DAMAGE_DONE_NEG[7];              // 0x000012E0
	DWORD PLAYER_FIELD_MOD_DAMAGE_DONE_PCT[7];              // 0x000012FC
	DWORD PLAYER_FIELD_BYTES;                               // 0x00001318
	DWORD PLAYER_AMMO_ID;                                   // 0x0000131C
	DWORD PLAYER_SELF_RES_SPELL;                            // 0x00001320
	DWORD PLAYER_FIELD_PVP_MEDALS;                          // 0x00001324
	DWORD PLAYER_FIELD_BUYBACK_PRICE_1[12];                 // 0x00001328
	DWORD PLAYER_FIELD_BUYBACK_TIMESTAMP_1[12];             // 0x00001358
	DWORD PLAYER_FIELD_SESSION_KILLS;                       // 0x00001388
	DWORD PLAYER_FIELD_YESTERDAY_KILLS;                     // 0x0000138C
	DWORD PLAYER_FIELD_LAST_WEEK_KILLS;                     // 0x00001390
	DWORD PLAYER_FIELD_THIS_WEEK_KILLS;                     // 0x00001394
	DWORD PLAYER_FIELD_THIS_WEEK_CONTRIBUTION;              // 0x00001398
	DWORD PLAYER_FIELD_LIFETIME_HONORBALE_KILLS;            // 0x0000139C
	DWORD PLAYER_FIELD_LIFETIME_DISHONORBALE_KILLS;         // 0x000013A0
	DWORD PLAYER_FIELD_YESTERDAY_CONTRIBUTION;              // 0x000013A4
	DWORD PLAYER_FIELD_LAST_WEEK_CONTRIBUTION;              // 0x000013A8
	DWORD PLAYER_FIELD_LAST_WEEK_RANK;                      // 0x000013AC
	byte PLAYER_FIELD_BYTES2[4];                            // 0x000013B0
	DWORD PLAYER_FIELD_WATCHED_FACTION_INDEX;               // 0x000013B4
	DWORD PLAYER_FIELD_COMBAT_RATING_1;                     // 0x000013B8
};

auto pfz = sizeof(PlayerFields);	//5052

struct GameObjectFields
{
	ObjectFields objectFields;
	QWORD OBJECT_FIELD_CREATED_BY;                          // 0x00000018
	DWORD GAMEOBJECT_DISPLAYID;                             // 0x00000020
	DWORD GAMEOBJECT_FLAGS;                                 // 0x00000024
	DWORD GAMEOBJECT_ROTATION[4];                           // 0x00000028
	DWORD GAMEOBJECT_STATE;                                 // 0x00000038
	DWORD GAMEOBJECT_POS_X;                                 // 0x0000003C
	DWORD GAMEOBJECT_POS_Y;                                 // 0x00000040
	DWORD GAMEOBJECT_POS_Z;                                 // 0x00000044
	DWORD GAMEOBJECT_FACING;                                // 0x00000048
	DWORD GAMEOBJECT_DYN_FLAGS;                             // 0x0000004C
	DWORD GAMEOBJECT_FACTION;                               // 0x00000050
	DWORD GAMEOBJECT_TYPE_ID;                               // 0x00000054
	DWORD GAMEOBJECT_LEVEL;                                 // 0x00000058
	DWORD GAMEOBJECT_ARTKIT;                                // 0x0000005C
	DWORD GAMEOBJECT_ANIMPROGRESS;                          // 0x00000060
	DWORD GAMEOBJECT_PADDING;                               // 0x00000064
};

struct DynamicObjectFields
{
	ObjectFields objectFields;
	QWORD DYNAMICOBJECT_CASTER;                             // 0x00000018
	byte  DYNAMICOBJECT_BYTES[4];                           // 0x00000020
	DWORD DYNAMICOBJECT_SPELLID;                            // 0x00000024
	DWORD DYNAMICOBJECT_RADIUS;                             // 0x00000028
	DWORD DYNAMICOBJECT_POS_X;                              // 0x0000002C
	DWORD DYNAMICOBJECT_POS_Y;                              // 0x00000030
	DWORD DYNAMICOBJECT_POS_Z;                              // 0x00000034
	DWORD DYNAMICOBJECT_FACING;                             // 0x00000038
	DWORD DYNAMICOBJECT_PAD;                                // 0x0000003C
};

struct CorpseFields
{
	ObjectFields objectFields;
	QWORD CORPSE_FIELD_OWNER;                               // 0x00000018
	DWORD CORPSE_FIELD_FACING;                              // 0x00000020
	DWORD CORPSE_FIELD_POS_X;                               // 0x00000024
	DWORD CORPSE_FIELD_POS_Y;                               // 0x00000028
	DWORD CORPSE_FIELD_POS_Z;                               // 0x0000002C
	DWORD CORPSE_FIELD_DISPLAY_ID;                          // 0x00000030
	DWORD CORPSE_FIELD_ITEM[19];                            // 0x00000034
	byte  CORPSE_FIELD_BYTES_1[4];                          // 0x00000080
	byte  CORPSE_FIELD_BYTES_2[4];                          // 0x00000084
	DWORD CORPSE_FIELD_GUILD;                               // 0x00000088
	DWORD CORPSE_FIELD_FLAGS;                               // 0x0000008C
	DWORD CORPSE_FIELD_DYNAMIC_FLAGS;                       // 0x00000090
	DWORD CORPSE_FIELD_PAD;                                 // 0x00000094
};

//----------------------------------------------------------------------------------------
#pragma pack()
