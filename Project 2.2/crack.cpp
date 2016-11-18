/*
Water        overcomes  Fire
Fire         overcomes  Wood
Wood         overcomes  Electricity
Electricity  overcomes  Water
*/

#include <iostream>
#include <cstdlib>
#include <ctime>

#define STUID "0556518"
#define WATER 1
#define FIRE 2
#define WOOD 3
#define ELECTRICITY 4

using namespace std;

int main(int argc, char *argv[]) 
{	
	cout << STUID << endl;

	srand(time(NULL));
	
	for(int n = 0; n < 1000; n++) {

		int boss_next_move = rand() % 4 + 1;

		if(boss_next_move == WATER)
			cout << ELECTRICITY << endl;
		else if(boss_next_move == FIRE)
			cout << WATER << endl;
		else if(boss_next_move == WOOD)
			cout << FIRE << endl;
		else if(boss_next_move == ELECTRICITY)
			cout << WOOD << endl;
	}

	return 0;
}
	