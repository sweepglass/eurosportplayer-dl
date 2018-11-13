cd video_dec
rm "./mylist.txt"
for i in `ls ./*.mp4 | sort -V`; do echo "file '$i'" >> "./mylist.txt"; done; 
cd ..
ffmpeg -f concat -safe 0 -i ./video_dec/mylist.txt -c copy ./video_dec/final.mp4 
