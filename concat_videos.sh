cd ./download/videos
rm "./mylist.txt"
for i in `ls ./*.mp4 | sort -V`; do echo "file '$i'" >> "./mylist.txt"; done; 
cd ../..
ffmpeg -f concat -safe 0 -i ./download/videos/mylist.txt -c copy ./download/final.mp4 
