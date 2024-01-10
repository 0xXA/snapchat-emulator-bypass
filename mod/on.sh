#!/data/data/com.termux/files/usr/bin/bash
#set -x;
NOW=$(date);
LIBPATH="/data/app/com.snapchat.android-1/lib/arm64";
TPATH="/data/data/com.termux/files/home/mod";
sudo date -s "2021-01-01";
mkdir -p ${TPATH}/.tmp;

sudo cp ${TPATH}/modlib/guffi /data/local/tmp/;
sudo chmod 755 /data/local/tmp/guffi;
sudo chown -R system:system /data/local/tmp/guffi;

for file in $(ls ${TPATH}/modlib/*.so | sed 's/.*modlib\///g'); do
	cp ${TPATH}/modlib/${file} ${TPATH}/.tmp/;
	sudo mv ${TPATH}/.tmp/${file} ${LIBPATH}/${file};
	sudo chmod 755 ${LIBPATH}/${file};
done

rm -rf ${TPATH}/.tmp;
unset file;
sudo find ${LIBPATH}/. -type f -exec touch {} +;
sudo chown -R system:system ${LIBPATH}/.;
sudo touch ${LIBPATH};
sudo date -s "${NOW}";
