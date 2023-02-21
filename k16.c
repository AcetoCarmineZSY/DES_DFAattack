#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//utile dans la recherche de K16
typedef struct message {
	unsigned long long chiffrerHexa;
	int chiffrerBinaire[64];
	int chiffrerBinairePermuter[64];
	int leftChiffrer[32];
	int rightChiffrer[32];
	int rightChiffrerExp[48];
	int sbox6Bits[6];
	int sbox6BitsXorer[6];
	int sbox4Bits[4]; 
} Message;

//utilise dans les recherche des 16 sous cles
typedef struct clef {
	int key48bit[48];
	int key56bit[56];
	int key64bitb[64];
	int key8bit[8];
} Key;

//utilise dans le DES, elle regroupe toute les variables necessaire au bon deroulement du DES
typedef struct des {
	int claireBinaire[64];
	int key64Bit[64];
	int claireBinaireIp[64];
	int right32Bit[32];
	int left32Bit[32];
	int right32BitPlus1[32];
	int left32BitPlus1[32];
	int right48Bit[48];
	int subKey[16][48];
	int chiffrerBinaire[64];
} DES;

//Initial permutation
static const int ip[64] = {
	58,50,42,34,26,18,10,2,
	60,52,44,36,28,20,12,4,
	62,54,46,38,30,22,14,6,
	64,56,48,40,32,24,16,8,
	57,49,41,33,25,17,9,1,
	59,51,43,35,27,19,11,3,
	61,53,45,37,29,21,13,5,
	63,55,47,39,31,23,15,7
};

//L'inverse de l'initial permutation
static const int ipMoin1[64] = {
	40,8,48,16,56,24,64,32,
	39,7,47,15,55,23,63,31,
	38,6,46,14,54,22,62,30,
	37,5,45,13,53,21,61,29,
	36,4,44,12,52,20,60,28,
	35,3,43,11,51,19,59,27,
	34,2,42,10,50,18,58,26,
	33,1,41,9,49,17,57,25
};

//Expansion
static const int e[48] = {
	32,1,2,3,4,5,
	4,5,6,7,8,9,
	8,9,10,11,12,13,
	12,13,14,15,16,17,
	16,17,18,19,20,21,
	20,21,22,23,24,25,
	24,25,26,27,28,29,
	28,29,30,31,32,1
};

//permutation dans la fonction interne f
static const int p[32] = {
	16,7,20,21,29,12,28,17,
	1,15,23,26,5,18,31,10,
	2,8,24,14,32,27,3,9,
	19,13,30,6,22,11,4,25
};

//permutation inverse dans la fonction interne f
static const int pMoin1[32] = {
	9,17,23,31,
	13,28,2,18,
	24,16,30,6,
	26,20,10,1,
	8,14,25,3,
	4,29,11,19,
	32,12,22,7,
	5,27,15,21
};

//Les 8 S-box contenu dans la fonction f
static const int sbox[8][4][16] = {
	{
		{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
		{0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
		{4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
		{15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
	},
	{
		{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
		{3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
		{0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
		{13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
	},
	{
		{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
		{13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
		{13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
		{1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
	},
	{
		{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
		{13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
		{10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
		{3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
	},
	{
		{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
		{14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
		{4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
		{11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
	},
	{
		{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
		{10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
		{9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
		{4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
	},
	{
		{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
		{13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
		{1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
		{6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
	},
	{
		{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
		{1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
		{7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
		{2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
	}
};

//permutation 1 dans le key schedul
static const int pc1[56] = {
	57,49,41,33,25,17,9,
	1,58,50,42,34,26,18,
	10,2,59,51,43,35,27,
	19,11,3,60,52,44,36,
	63,55,47,39,31,23,15,
	7,62,54,46,38,30,22,
	14,6,61,53,45,37,29,
	21,13,5,28,20,12,4
};

//permutation 1 inverse dans le key schedul
static const int pc1Moin1[64] = {
	8,16,24,56,52,44,36,0,
	7,15,23,55,51,43,35,0,	
	6,14,22,54,50,42,34,0,
	5,13,21,53,49,41,33,0,	
	4,12,20,28,48,40,32,0,	
	3,11,19,27,47,39,31,0,
	2,10,18,26,46,38,30,0,	
	1,9,17,25,45,37,29,0
};

//permutation 2 dans le key schedul qui fait passer la clef de 56 a 48 bits
static const int pc2[48] = {
	14,17,11,24,1,5,
	3,28,15,6,21,10,
	23,19,12,4,26,8,
	16,7,27,20,13,2,
	41,52,31,37,47,55,
	30,40,51,45,33,48,
	44,49,39,56,34,53,
	46,42,50,36,29,32
};

//permutation 2 inverse dans le key schedul
static const int pc2Moin1[56] = {
	5,24,7,16,6,10,20,	
	18,0,12,3,15,23,1,
	9,19,2,0,14,22,11,	
	0,13,4,0,17,21,8,
	47,31,27,48,35,41,0,
	46,28,0,39,32,25,44,
	0,37,34,43,29,36,38,	
	45,33,26,42,0,30,40
};


static const unsigned long long messageClaire = 0x04A2767F3BB0E9AB;

static const unsigned long long chiffrerJuste = 0xFFE5EA421F43F4DE;

static const unsigned long long chiffrerFaux[32] = {
	0xFDE1EA461F42F4DA, 
	0xFFF7EA021F43F4DE, 
	0xFFF5E8461F43F4DE, 
	0xFEA5EA001F42F4DE, 
	0xFEA5EA460D42F4DE, 
	0xFFA5EE421F41F4DE, 
	0xFEA5EE420F43F6DE, 
	0xFEA5EE435F57F4DC, 
	0xF6A5EA434F53F4DE, 
	0xFFEDEA435F57F4DE, 
	0xFFE5E2435F43F4DE, 
	0xBFE5FA4A1F17F4DF, 
	0xFFE5EA425713F4DF, 
	0xFFE5FA421F0BF4DF, 
	0xBFE5EA421F43FCDF, 
	0xBFE5FA421B03F496, 
	0xDFE5FA421B03F49E, 
	0xFFC5EA421B43F59E, 
	0xFFE5CA421B43E49E, 
	0xEBE5EB621B43E59E, 
	0xFBE5AB423B43E49E, 
	0xEBE5EA421F63F4DE, 
	0xFBE5EB421F43D4DE, 
	0xEFE5AA521F43B4FE, 
	0x6FE5AB521E43B0DE, 
	0xFF65EA521E43F0DE, 
	0xFFE56A521F43B4DE, 
	0xFFE4EAD21F43F0DA, 
	0xFFE0EA429E43B4DE, 
	0xFFE0EA421FC3F4CE, 
	0xFFE4EA421F4374DA, 
	0xFFF0EA421F42F44A 
};

//passer d'un unsigned long long en hexa en un tableau de bit
void hexatobinary(int *tabResult, unsigned long long hexa, int nbrHexa){
	unsigned long long tmp = hexa;
	int entier;
	int compteur = nbrHexa*4-1;
	for(int j=0;j<nbrHexa;j++){
		entier = tmp & 0xF;
		for(int i=0;i<4;i++){
			tabResult[compteur] = entier % 2;
			entier = entier / 2;
			compteur--;
		}
		tmp = tmp >> 4;
	}

}

//transformer un entier en un tableau de bit
void decimaltobinary(int *tabResult, int decimal, int nbrBit){
	int entier = decimal;
	for(int i=nbrBit-1; i>=0; i--){
		tabResult[i] = entier % 2;
		entier = entier /2;
	}
}

//élevé a la puissance
unsigned long long puissance(int a,int b){
	if(b == 0){
		return 1;
	} else {
		return a*puissance(a,b-1);
	}
}

//transformer un tableau de bit en un entier
int TabtoInt(int *tab,int nbrBit){	
	int nombre=0;
	int i=0,j=nbrBit-1;
	while(j>=0){
		if(tab[j] != 0){
			nombre += puissance(2,i);
		}
		i++;
		j--;
	}
	return nombre;
}

//transformer un tableau de bit en un hexadecimal
unsigned long long TabtoLong(int *tab,int nbrBit){	
	unsigned long long nombre=0;
	int i=0,j=nbrBit-1;
	while(j>=0){
		if(tab[j] != 0){
			nombre += puissance(2,i);
		}
		i++;
		j--;
	}
	return nombre;
}

//gere toute les permutation y compris l'expension
void Permutation(int *resultat,int *aPermuter,const int *tablePermutation, int nbrBit){
	for(int i=0;i<nbrBit;i++){
		if(tablePermutation[i] != 0){
			resultat[i] = aPermuter[tablePermutation[i]-1];
		}
	}
}

//divise un tableau de bit en 2 tableau de meme longueur
void splitTab(int *completTab,int *leftTab,int *rightTab, int nbrBit){
	for(int i=0;i<nbrBit;i++){
		leftTab[i] = completTab[i];
		rightTab[i] = completTab[i+nbrBit];
	}
}

//applique un XOR entre 2 tableau de bit
void xor(int *tabResult, int *premierK, int *deuxiemeK, int nbrBit){
	for(int i=0;i<nbrBit;i++){
		tabResult[i] = premierK[i] ^ deuxiemeK[i];
	}
}

//trouve la position du bit fauter
int bitFauter(int *tabJuste, int *tabFaux) {
	int tabxor[33] = {0};
	xor(tabxor, tabJuste, tabFaux, 32);
	for(int j=0;j<32;j++){
		if(tabxor[j] == 1){
			return j;
		}
	}
	return -1;
}

//la boite de substitution qui transforme 6 bit en 4 bit selon la S-box choisi
void Sboxfonc(int *resultat, int *entrer, int numSbox){
	int row = 0;
	int column = 0;
	row = entrer[0]*2+entrer[5];
	int i=0,j=4;
	while(j>0){
		if(entrer[j] != 0){
			column += puissance(2,i);
		}
		i++;
		j--;
	}
	unsigned long long resultat4bit = sbox[numSbox][row][column];
	hexatobinary(resultat, resultat4bit,1);
}

//s'occupe de retrouver le L16 et le L16 fauter
void obtenirR16L16(unsigned long long hexa,Message *m){
	m->chiffrerHexa = hexa;
	hexatobinary(m->chiffrerBinaire,hexa,16);
	Permutation(m->chiffrerBinairePermuter, m->chiffrerBinaire, ip, 64);
	splitTab(m->chiffrerBinairePermuter,m->leftChiffrer,m->rightChiffrer, 32);
	
}

//On extrer 6 bit une position bien defini au niveau des S-box
void extraire6Bits(Message *m, int position) {
	for(int i=0; i<6; i++) {
		m->sbox6Bits[i] = m->rightChiffrerExp[6*position+i];
	}
}

//Compare deux tableau de meme taille
int egale(int *tab1, int *tab2, int nbrBit){
	for(int i=0; i<nbrBit; i++){
		if(tab1[i] != tab2[i])
			return 0;
	}
	return 1;
}

//traite les resultat de la recherche exhaustive pour trouver le bon K16
unsigned long long k16enHexa(int tabK16[8][64]){
	unsigned long long resultat = 0;
	int tab[8] = {0};
	int tabclef[6] = {0};
	int tabresult[64] = {0};
	for(int i=0; i<8; i++){
		for(int j=0;j<64;j++){
			if(tabK16[i][j] == 6)
				tab[i] = j;
		}
		printf("%d\n", tab[i]);
		decimaltobinary(tabclef, tab[i], 6);
		for(int j=0; j<6;j++){
			tabresult[i*6+j] = tabclef[j];
		}
	}
	resultat = TabtoLong(tabresult,48);
	return resultat;
}

//Fait la recherche exhaustive pour trouver la clef K15
unsigned long long rechercheExostive(const unsigned long long LechiffrerJuste, const unsigned long long *LeschiffrerFaux){
	Message juste;
	Message faux;
	unsigned long long aRetourner = 0;
	int resultat[8][64] = {0};
	obtenirR16L16(LechiffrerJuste,&juste);
	int leftPmoin1[32] = {0};
	int resultatxorLeft[32] = {0};
	for(int w=0;w<32;w++){
		obtenirR16L16(LeschiffrerFaux[w],&faux);
		xor(resultatxorLeft,juste.leftChiffrer,faux.leftChiffrer,32);
		Permutation(leftPmoin1, resultatxorLeft, pMoin1, 32);
		int bitfaux = bitFauter(juste.rightChiffrer,faux.rightChiffrer);
		//printf("bit faux : %d\n", bitfaux);
		Permutation(juste.rightChiffrerExp,juste.rightChiffrer,e,48);
		Permutation(faux.rightChiffrerExp,faux.rightChiffrer,e,48);
		int resSbox[4] = {0};
		int resLeftJuste[4] = {0};
		int key[6] = {0};
		for(int i=0; i<48; i++){
			if(e[i] == (bitfaux+1)){
				extraire6Bits(&juste,i/6);
				extraire6Bits(&faux,i/6);
				for(int y=0; y<4; y++){
					resLeftJuste[y] = leftPmoin1[4*(i/6)+y];
				}
				for(int j=0; j<64; j++){
					decimaltobinary(key,j,6);
					xor(juste.sbox6BitsXorer,juste.sbox6Bits,key,6);
					decimaltobinary(key,j,6);
					xor(faux.sbox6BitsXorer,faux.sbox6Bits,key,6);
					Sboxfonc(juste.sbox4Bits, juste.sbox6BitsXorer, i/6);
					Sboxfonc(faux.sbox4Bits, faux.sbox6BitsXorer, i/6);
					xor(resSbox,juste.sbox4Bits,faux.sbox4Bits,4);
					if(egale(resLeftJuste,resSbox,4)) {
						resultat[i/6][TabtoInt(key,6)]++;
					}
				}
			}
		}
	}
	aRetourner = k16enHexa(resultat);
	return aRetourner;
}

//initiatilse le tableau de bit a 0
void initTab(int *tab, int nbrBit){
	for(int i=0;i<nbrBit;i++){
		tab[i] = 0;
	}
}

//S'occupe de shifter les bit de nbrShift fois vers la gauche
void shiftGauche(int *resultat, int *tabAshifter, int nbrShift, int nbrBit){
	for(int i=-nbrShift; i<nbrBit-nbrShift; i++){
		if(i<0) {
			resultat[i+nbrBit] = tabAshifter[i+nbrShift];
		} else {
			resultat[i] = tabAshifter[i+nbrShift];	
		}
	}
}

//On fusionne deux tableau de meme dimension
void fusionTab(int *resultat, int *leftTab, int *rightTab, int nbrBit){
	for(int i=0; i<nbrBit; i++){
		resultat[i] = leftTab[i];
		resultat[i+nbrBit] =rightTab[i];
	}
}

//Genere les 16 clef de K0 a K15 dans le DES
void generationSubKey(int Les16SubKey[][48], int *key64Bit){
	int v[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	int key56bit[56] = {0};
	int key48bit[48] = {0};
	int tabSplit[2][28] = {0};
	int tabSplitRes[2][28] = {0};
	Permutation(key56bit, key64Bit, pc1, 56);
	for(int i=0; i<16; i++) {
		splitTab(key56bit,tabSplit[0],tabSplit[1], 28);
		shiftGauche(tabSplitRes[0], tabSplit[0], v[i], 28);
		shiftGauche(tabSplitRes[1], tabSplit[1], v[i], 28);
		fusionTab(key56bit, tabSplitRes[0], tabSplitRes[1], 28);
		Permutation(Les16SubKey[i], key56bit, pc2, 48);
	}
}

//Fonction interne F du DES
void f(int *resultat, int *Ri, int *Ki){
	int right48b[48] = {0};
	int resultatXor[48] = {0};
	int entrerSbox[6] = {0};
	int sortiSbox[4] = {0};
	int sorti32bit[32] = {0};
	Permutation(right48b,Ri,e,48);
	xor(resultatXor,right48b,Ki,48);
	for(int j=0;j<8;j++){
		for(int i=0; i<6; i++) {
			entrerSbox[i] = resultatXor[6*j+i];
		}
		Sboxfonc(sortiSbox, entrerSbox, j);
		for(int i=0;i<4;i++){
			sorti32bit[j*4+i] = sortiSbox[i];
		}
	}
	Permutation(resultat, sorti32bit, p, 32);
}

//Sert a copier un tableau dans un autre de meme dimension
void copieTab(int *resultat, int * aCopier, int nbrBit){
	for(int i=0; i<nbrBit; i++){
		resultat[i] = aCopier[i];
	}
}

//DES : Prend en entrer un message claire et une clef pour donner un message chiffrer
unsigned long long fonctionDES(unsigned long long claire, unsigned long long k64){
	DES d;
	int resultatF[32] = {0};
	int resultatConcat[64] = {0};
	hexatobinary(d.claireBinaire, claire, 16);
	hexatobinary(d.key64Bit, k64, 16);
	Permutation(d.claireBinaireIp, d.claireBinaire, ip, 64);
	splitTab(d.claireBinaireIp, d.left32Bit, d.right32Bit, 32);
	generationSubKey(d.subKey, d.key64Bit);
	for(int i=0; i<16; i++){
		copieTab(d.left32BitPlus1, d.right32Bit, 32);
		f(resultatF, d.right32Bit, d.subKey[i]);
		xor(d.right32BitPlus1, d.left32Bit, resultatF, 32);
		copieTab(d.left32Bit, d.left32BitPlus1, 32);
		copieTab(d.right32Bit, d.right32BitPlus1, 32);
	}
	fusionTab(resultatConcat, d.right32Bit, d.left32Bit, 32);
	Permutation(d.chiffrerBinaire, resultatConcat, ipMoin1, 64);
	return TabtoLong(d.chiffrerBinaire,64);
}

//Sert a obtenir les 56 bit juste de la clef de chiffrement
//(il restera que les bit de parité a trouver)
unsigned long long getK56bit(unsigned long long claire, unsigned long long chiffrer, unsigned long long k16){
	Key k;
	initTab(k.key48bit,48);
	initTab(k.key56bit,56);
	initTab(k.key64bitb,64);
	hexatobinary(k.key48bit,k16,12);
	Permutation(k.key56bit, k.key48bit, pc2Moin1, 56);
	Permutation(k.key64bitb, k.key56bit, pc1Moin1, 64);
	int position8bit[8] = {14,15,19,20,51,54,58,60};
	int i=0;
	while(i<256) {
		decimaltobinary(k.key8bit,i,8);
		for(int j=0;j<8;j++){
			k.key64bitb[position8bit[j]-1] = k.key8bit[j];
		}
		unsigned long long clef = TabtoLong(k.key64bitb,64);
		if(chiffrer == fonctionDES(claire,clef)){
			return clef;
		}
		i++;
	}
	return 0;
}

//Renvoi la clef de chiffrement complete de 64 bits
unsigned long long getK64bitParite(unsigned long long claire, unsigned long long chiffrer, unsigned long long k16){
	int compteur = 0;
	int tabClefB[64] = {0};
	hexatobinary(tabClefB, getK56bit(claire, chiffrer, k16), 16);
	for(int i=0; i<64;i++){
		printf("%d", tabClefB[i]);
		if((i+1)%8 == 0)
			printf(" ");
	}
	printf("\n");
	for(int i=1; i<65; i++) {
		if((i%8) == 0) {
			if(compteur%2 == 1){
				tabClefB[i-1] = 0;
			}else {
				tabClefB[i-1] = 1;
			}
			compteur = 0;
		}else {
			compteur += tabClefB[i-1];
		}
	}
	for(int i=0; i<64;i++){
		printf("%d", tabClefB[i]);
		if((i+1)%8 == 0)
			printf(" ");
	}
	printf("\n");
	return TabtoLong(tabClefB,64);
}

int main(){

	unsigned long long K_16 = rechercheExostive(chiffrerJuste,chiffrerFaux);
	printf("K16: %llx\n", K_16); 
	printf("Cle : %llx\n", getK64bitParite(messageClaire, chiffrerJuste, K_16));
		
	return 0;
}