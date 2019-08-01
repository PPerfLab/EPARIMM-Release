rm -f ./ring0manager.ko
rm -f *.o
sudo rmmod ring0manager
sudo make
sudo dmesg -C
sudo insmod ./ring0manager.ko
echo
find ring0manager.ko
echo
