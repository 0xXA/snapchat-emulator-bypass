#!/data/data/com.termux/files/usr/bin/bash
#set -x;
NOW=$(date);
LIBPATH="/data/app/com.snapchat.android-1/lib/arm64";
TPATH="/data/data/com.termux/files/home/mod";
sudo date -s "2021-01-01";
mkdir -p ${TPATH}/.tmp;
for file in $(ls ${TPATH}/orglib/*.so | sed 's/.*orglib\///g');do
	cp ${TPATH}/orglib/${file} ${TPATH}/.tmp/;
	sudo mv ${TPATH}/.tmp/${file} ${LIBPATH}/${file};
	sudo chmod 755 ${LIBPATH}/${file};
done
rm -rf ${TPATH}/.tmp;
unset file;
sudo find ${LIBPATH}/. -type f -exec touch {} +;
sudo chown -R system:system ${LIBPATH}/.;
sudo touch ${LIBPATH};
sudo date -s "${NOW}";
