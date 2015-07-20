import tshark
import sys
import os

def init_tshark(files):
	t_shark = tshark.Tshark()
	t_shark.save_multiple_files(files)

if __name__ == "__main__":
	path = sys.argv[1]
	files=[]

	if os.path.isfile(path):
		files = [ path ]
	else:
		files = [ path + '/' + f for f in os.listdir(path) if os.path.isfile(os.path.join(path,f)) ]

	init_tshark(files)