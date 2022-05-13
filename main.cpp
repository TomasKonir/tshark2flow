#include <QJsonDocument>
#include <QElapsedTimer>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonValue>
#include <QProcess>
#include <QThread>
#include <QFileInfo>
#include <QDateTime>
#include <QHash>
#include <QList>
#include <QFile>
#include <QSet>
#include <QDebug>
#include "signal.h"

enum FieldOperation {
	OP_UNDEFINED = -1,
	OP_SKIP = 0,
	OP_FIRST = 1,
	OP_LAST = 2,
	OP_SUM = 3,
	OP_ARRAY = 4,
	OP_OR = 5,
};

QHash<QString,FieldOperation> operationString = {
	{"undefined",OP_UNDEFINED},
	{"skip",OP_SKIP},
	{"first",OP_FIRST},
	{"last",OP_LAST},
	{"sum",OP_SUM},
	{"array",OP_ARRAY},
	{"or",OP_OR}
};

typedef struct {
	bool                    flipped;
	QHash<QString,QVariant> fields;
}TsharkPacket;

typedef struct {
	bool                    firstFlipped; //first packet is flipped and flow must be flipped back before export
	qint64                  started;
	qint64                  updated; //update timestamp
	QHash<QString,QVariant> biflowFields[2];
	QHash<QString,QVariant> fields;
}TsharkFlow;

QHash<QString,QJsonValue>        skippedFields;
QHash<QString,FieldOperation>    processedFields;
QStringList                      identFields;
QStringList                      hexaFormat;
QHash<QString,QString>           transformFields;
QList<QStringList>               biflowTests;
QList<QStringList>               biflowFlips;
QStringList                      biflowFields;
bool                             prettyJson;

//data queue
QHash<QByteArray,TsharkFlow*>    queue;
int                              queueLimit = (1024*16);
qint64                           queueInactiveInterval = 30000;
qint64                           queueActiveInterval = 300000;
qint64                           queueLastCheck = 0;
volatile bool                    ctrl_c = false;
bool							 stats = false;

void sigHandler(int s) {
	switch (s) {
		case SIGINT:
		case SIGQUIT:
			if(ctrl_c){
				qInfo() << "Forced exit";
				exit(-1);
			}
			ctrl_c = true;
		break;
	}
	signal(SIGINT, &sigHandler);
	signal(SIGQUIT, &sigHandler);
}


QJsonObject readConfig(QString path){
	QJsonObject ret;
	QFile in(path);
    QJsonParseError err;
    if(in.size() < (1024*1024*16) && in.open(QIODevice::ReadOnly)){
        ret = QJsonDocument::fromJson(in.readAll(),&err).object();
        if(err.error != QJsonParseError::NoError){
            qInfo() << "Config parse error:" << err.offset << err.errorString();
        }
	}
	return(ret);
}

QString json2String(QJsonObject o,bool pretty){
	QJsonDocument jDoc(o);
	return(QString::fromUtf8(jDoc.toJson(pretty ? QJsonDocument::Indented : QJsonDocument::Compact)));
}

QTextStream& qStdOut(){
	static QTextStream ts( stdout );
	return ts;
}

QVariantList optimizeArray(QJsonValue &a){
	QVariantList ret;
	if(a.isArray()){
        for(const auto &it : a.toArray()){
            QVariant vv = it.toVariant();
			if(!ret.contains(vv)){
				ret << vv;
			}
		}
	}
	return(ret);
}

void obj2packet(QJsonObject &packet, TsharkPacket &tp, bool clean = false){
	if(clean){
		QString timestamp = QDateTime::fromMSecsSinceEpoch(packet.value("timestamp").toString().toULong()).toString("yyyy-MM-dd hh:mm:ss.zzz");
		tp.flipped = false;
		tp.fields.clear();
		tp.fields.insert("flow_start",timestamp);
		tp.fields.insert("flow_end",timestamp);
		tp.fields.insert("packets",1LL);
	}
	foreach(QString k, packet.keys()){
		QJsonValue v = packet.value(k);
		if(v.isObject()){
			QJsonObject o = v.toObject();
			obj2packet(o,tp);
		} else {
			FieldOperation op = processedFields.value(k,OP_UNDEFINED);
			if(op == OP_UNDEFINED){
				if(!skippedFields.contains(k)){
					skippedFields.insert(k,v);
				}
			} else if(op == OP_SKIP){
				//skip value
			} else {
				if(v.isArray() && v.toArray().count() == 1){
					v = v.toArray()[0];
				}
                switch(v.type()){
					case QJsonValue::String :{
							QString s = v.toString();
							bool numberOk;
							qint64 n = s.toLongLong(&numberOk,10);
							if(numberOk){
								tp.fields.insert(k,n);
							} else {
								tp.fields.insert(k,s);
							}
							break;
						}
					case QJsonValue::Array :{
							tp.fields.insert(k,optimizeArray(v));
							break;
						}
					default:{
							qInfo() << "Invalid value:" << k << v;
							break;
						}
				}
			}
		}
	}
}

void packetFlip(TsharkPacket &packet){
	foreach(QStringList l, biflowTests){
		QString t0 = l[0];
		QString t1 = l[1];
		if(packet.fields.contains(t0) && packet.fields.contains(t1)){
			QString v0 = packet.fields.value(t0).toString();
			QString v1 = packet.fields.value(t1).toString();
			if(v0 > v1){
				packet.flipped = true;
				break;
			}
		}
	}
	if(packet.flipped){
		foreach(QStringList l, biflowFlips){
			QString t0 = l[0];
			QString t1 = l[1];
			if(packet.fields.contains(t0) && packet.fields.contains(t1)){
				QVariant v0 = packet.fields.value(t0);
				QVariant v1 = packet.fields.value(t1);
				packet.fields.insert(t0,v1);
				packet.fields.insert(t1,v0);
			}
		}
	}
}

void flowFlip(TsharkFlow *flow){
	if(!flow->firstFlipped){
		return;
	}
	foreach(QStringList l, biflowFlips){
		QString t0 = l[0];
		QString t1 = l[1];
		if(flow->fields.contains(t0) && flow->fields.contains(t1)){
			QVariant v0 = flow->fields.value(t0);
			QVariant v1 = flow->fields.value(t1);
			flow->fields.insert(t0,v1);
			flow->fields.insert(t1,v0);
		}
	}
}

QByteArray packet2ident(const TsharkPacket &packet){
	QByteArray ret;
	foreach(QString s, identFields){
		if(packet.fields.contains(s)){
			QVariant v = packet.fields.value(s);
            if(v.typeId() == QMetaType::QString){
				ret += v.toString().toUtf8();
            } else if(v.typeId() == QMetaType::LongLong){
				qint64 d = v.toLongLong();
				ret.append(reinterpret_cast<char*>(&d),sizeof(qint64));
            } else if(v.typeId() == QMetaType::QVariantList){
				QVariantList lv = v.toList();
				foreach(QVariant vv, lv){
                    if(vv.typeId() == QMetaType::QString){
						ret += vv.toString().toUtf8();
                    } else if(vv.typeId() == QMetaType::LongLong){
						qint64 d = vv.toLongLong();
						ret.append(reinterpret_cast<char*>(&d),sizeof(qint64));
					} else {
						qInfo() << "Invalid value for ident" << s << v;
					}
				}
			} else {
				qInfo() << "Invalid value for ident" << s << v;
			}
		}
	}
	return(ret);
}

QJsonObject hash2json(QHash<QString,QVariant> &hash){
	QJsonObject ret;
	foreach(QString k, hash.keys()){
		QVariant v = hash.value(k);
		QString kk = transformFields.value(k,k);
        if(v.typeId() == QMetaType::LongLong){
			if(hexaFormat.contains(k)){
				ret.insert(kk,"0x" + QString::number(v.toLongLong(),16));
			} else {
				ret.insert(kk,v.toDouble());
			}
        } else if(v.typeId() == QMetaType::QString){
			ret.insert(kk,v.toString());
        } else if(v.typeId() == QMetaType::QVariantList){
			QJsonArray a;
			foreach(QVariant vv, v.toList()){
                if(vv.typeId() == QMetaType::QString){
					a<< vv.toString();
                } else if(vv.typeId() == QMetaType::LongLong){
					a << vv.toDouble();
				}
			}
			ret.insert(kk,a);
		} else {
			qInfo() << "Invalid type:" << k << v;
		}
	}
	return(ret);
}

QJsonObject flow2json(TsharkFlow *flow){
	flowFlip(flow);
	QJsonObject ret = hash2json(flow->fields);
	QJsonObject biflow0;
	QJsonObject biflow1;
	QJsonArray biflow;
	if(flow->firstFlipped){
		biflow0 = hash2json(flow->biflowFields[1]);
		biflow1 = hash2json(flow->biflowFields[0]);
	} else {
		biflow0 = hash2json(flow->biflowFields[0]);
		biflow1 = hash2json(flow->biflowFields[1]);
	}
	if(!biflow0.isEmpty()){
		biflow << biflow0;
	}
	if(!biflow1.isEmpty()){
		biflow << biflow1;
	}
	if(biflow.count()){
		ret.insert("biflow",biflow);
	}
	return(ret);
}

void flushQueue(){
	foreach(TsharkFlow *f,queue.values()){
		qStdOut() << json2String(flow2json(f),prettyJson) << "\n";
		delete f;
	}
	queue.clear();
}

void queueCheck(qint64 now){
	now -= queueInactiveInterval;
//	qInfo() << "QueueCheck started:" << queue.count();
	foreach(QByteArray k,queue.keys()){
		TsharkFlow *f = queue.value(k);
		if(f->updated < now){
			qStdOut() << json2String(flow2json(f),prettyJson) << "\n";
			delete(f);
			queue.remove(k);
		}
	}
//	qInfo() << "QueueCheck finished:" << queue.count();
}

void packetProcess(const TsharkPacket &packet, const QByteArray &ident, const qint64 now){
	TsharkFlow *flow = queue.value(ident,nullptr);
	if(flow == nullptr){
		flow = new TsharkFlow;
		flow->firstFlipped = false;
		flow->updated = flow->started = now;
		foreach(QString k, packet.fields.keys()){
			QVariant v = packet.fields.value(k);
			QHash<QString,QVariant> *fields = &flow->fields;
			FieldOperation op = processedFields.value(k);
			if(biflowTests.length() && biflowFields.contains(k)){
				if(packet.flipped){
					flow->firstFlipped = true;
					fields = &flow->biflowFields[1];
				} else {
					fields = &flow->biflowFields[0];
				}
			}
			switch(op){
				case OP_FIRST:{
						fields->insert(k,v);
						break;
					}
				case OP_LAST:{
						fields->insert(k,v);
						break;
					}
				case OP_SUM:{
						fields->insert(k,v);
						break;
					}
				case OP_OR:{
						bool numberOk;
						qint64 n = v.toString().toLongLong(&numberOk,0);
						if(numberOk){
							fields->insert(k,n);
						}
						
						break;
					}
				case OP_ARRAY:{
                        if(v.typeId() == QMetaType::QVariantList){
							fields->insert(k,v);
						} else {
							fields->insert(k,QVariantList() << v);
						}
						break;
					}
				default:
					break;
			}
		}
		queue.insert(ident,flow);
	} else {
		flow->updated = now;
		foreach(QString k, packet.fields.keys()){
			QVariant v = packet.fields.value(k);
			QHash<QString,QVariant> *fields = &flow->fields;
			FieldOperation op = processedFields.value(k);
			if(biflowTests.length() && biflowFields.contains(k)){
				if(packet.flipped){
					fields = &flow->biflowFields[1];
				} else {
					fields = &flow->biflowFields[0];
				}
			}
			switch(op){
				case OP_FIRST:{
						if(!fields->contains(k)){
							fields->insert(k,v);
						}
						break;
					}
				case OP_LAST:{
						fields->insert(k,v);
						break;
					}
				case OP_SUM:{
						qint64 d = v.toLongLong();
						if(fields->contains(k)){
							d +=  fields->value(k).toLongLong();
						}
						fields->insert(k,d);
						break;
					}
				case OP_OR:{
						bool numberOk;
						qint64 n = v.toString().toLongLong(&numberOk,0);
						if(numberOk){
							if(fields->contains(k)){
								n |=  fields->value(k).toLongLong();
							}
							fields->insert(k,n);
						}
						break;
					}
				case OP_ARRAY:{
						QVariantList lv;
						if(fields->contains(k)){
							lv = fields->value(k).toList();
						}
                        if(v.typeId() == QMetaType::QVariantList){
							foreach(QVariant vv, v.toList()){
								if(!lv.contains(vv)){
									lv << vv;
								}
							}
						} else {
							if(!lv.contains(v)){
								lv << v;
							}
						}
						fields->insert(k,lv);
						break;
					}
				default:
					break;
			}
		}
		if((flow->updated - flow->started) > queueActiveInterval){
			qStdOut() << json2String(flow2json(flow),prettyJson) << "\n";
			qStdOut().flush();
			queue.remove(ident);
		}
	}
	if(queue.count() > queueLimit || qAbs(now - queueLastCheck) > (queueInactiveInterval/4)){
		queueLastCheck = now;
		queueCheck(now);
	}
}


int main(int argc, char *argv[]){
	QJsonObject config;
	QProcess    tshark;
	QString     pcap;
	quint64     packets = 0;
	bool        printUnknown;
	QStringList tsharkFields;

	if(argc < 3){
		qInfo() << "Usage:" << argv[0] << "config.json" << "file.pcap | device";
		return(-1);
	}

	signal(SIGINT, &sigHandler);
	signal(SIGQUIT, &sigHandler);

	pcap = QString::fromUtf8(argv[2]);
	config = readConfig(argv[1]);
	if(config.isEmpty()){
        qInfo() << "Invalid config file";
		return(-1);
	}
	prettyJson = config.value("pretty").toBool();
	printUnknown = config.value("printUnknown").toBool();
	queueLimit = config.value("queueLimit").toInt();
	queueInactiveInterval = config.value("queueInactiveInterval").toInt(5000);
	queueActiveInterval = config.value("queueActiveInterval").toInt(15000);	
	//insert default fields
	processedFields.insert("packets",OP_SUM);
	processedFields.insert("flow_start",OP_FIRST);
	processedFields.insert("flow_end",OP_LAST);
	if(config.contains("fields") && config.value("fields").isObject()){
		QJsonObject fo = config.value("fields").toObject();
		foreach(QString k, fo.keys()){
            QString kv = fo.value(k).toString();
			if(!operationString.contains(kv)){
                qInfo() << "Invalid field value" << fo.value(k);
			} else {
                tsharkFields << "-e" << k;
                processedFields.insert(k.replace(".","_"),operationString.value(kv));
			}
		}
    }
    //insert ident fields
    if(config.contains("ident") && config.value("ident").isArray()){
        QJsonArray sa = config.value("ident").toArray();
        foreach(QJsonValue v, sa){
            if(v.isString()){
                QString f = v.toString().replace(".","_");
                if(!processedFields.contains(f)){
                    qInfo() << "Field:" << v << "is missing in processed fields and probably will not work";
                }
                identFields << f;
            } else {
                qInfo() << "Unknown ident type:" << v;
            }
        }
    }
	if(config.contains("transform") && config.value("transform").isObject()){
		QJsonObject fo = config.value("transform").toObject();
		foreach(QString k, fo.keys()){
			QString kv = fo.value(k).toString();
			if(kv.length()){
                transformFields.insert(k.replace(".","_"),kv);
			}
		}
	}
	if(config.contains("skip") && config.value("skip").isArray()){
		QJsonArray sa = config.value("skip").toArray();
		foreach(QJsonValue v, sa){
			if(v.isString()){
                QString s = v.toString();
                QString ss = s;
                ss.replace(".","_");
                if(processedFields.contains(ss) && processedFields.value(ss) != OP_SKIP){
					qInfo() << "Warning: skip field" << s << "is already in processed fields";
				} else {
                    processedFields.insert(ss,OP_SKIP);
				}
			} else {
				qInfo() << "Unknown skip type:" << v;
			}
		}
	}
	if(config.contains("hexa") && config.value("hexa").isArray()){
		QJsonArray sa = config.value("hexa").toArray();
		foreach(QJsonValue v, sa){
			if(v.isString()){
                hexaFormat << v.toString().replace(".","_");
			} else {
				qInfo() << "Unknown hexa type:" << v;
			}
		}
	}
	if(config.contains("biflow") && config.value("biflow").isObject()){
		QJsonObject biflow = config.value("biflow").toObject();
		if(biflow.contains("tests") && biflow.value("tests").isArray()){
			QJsonArray tests = biflow.value("tests").toArray();
			foreach(QJsonValue v, tests){
				QJsonArray a = v.toArray();
				if(a.count() == 2){
					QStringList l;
                    l << a[0].toString().replace(".","_") << a[1].toString().replace(".","_");
					biflowTests << l;
				}
			}
		}
		if(biflow.contains("flips") && biflow.value("flips").isArray()){
			QJsonArray tests = biflow.value("flips").toArray();
			foreach(QJsonValue v, tests){
				QJsonArray a = v.toArray();
				if(a.count() == 2){
					QStringList l;
                    l << a[0].toString().replace(".","_") << a[1].toString().replace(".","_");
					biflowFlips << l;
				}
			}
		}
		if(biflow.contains("bi_fields") && biflow.value("bi_fields").isArray()){
			QJsonArray tests = biflow.value("bi_fields").toArray();
			biflowFields << "packets";
			foreach(QJsonValue v, tests){
				if(v.isString()){
                    biflowFields << v.toString().replace(".","_");
				}
			}
		}
	}

    QStringList params;
    params << "-o" << "tcp.desegment_tcp_streams:false" << "-M" << "100000" << "-l" << "-T" << "ek" << "-n" << tsharkFields;
    if(QFile(pcap).exists()){
		stats = true;
		tshark.setProcessChannelMode(QProcess::ForwardedErrorChannel);
		tshark.setReadChannel(QProcess::StandardOutput);
        params << "-r" << pcap;
        tshark.start("tshark",params);
	} else {
		stats = false;
		tshark.setProcessChannelMode(QProcess::SeparateChannels);
		tshark.setReadChannel(QProcess::StandardOutput);
        params << "-i" << pcap;
        tshark.start("tshark",params);
	}
	tshark.waitForStarted();
	TsharkPacket packet;
	QElapsedTimer elapsed;
	elapsed.start();
	while(tshark.state() == QProcess::Running || !tshark.atEnd()){
		tshark.waitForReadyRead(100);
		QByteArray err = tshark.readAllStandardError();
		if(err.length() && stats){
			qInfo() << QString::fromUtf8(err);
		}
		if(tshark.canReadLine()){
			QByteArray line = tshark.readLine();
			QJsonObject obj = QJsonDocument::fromJson(line).object();
			if(obj.isEmpty()){
				qInfo() << "Empty or invalid line" << line;
				continue;
			} else {
				if(!obj.contains("timestamp")){
					continue;
				}
				qint64 now = obj.value("timestamp").toString().toLongLong();
				obj2packet(obj,packet,true);
				packetFlip(packet);
				QByteArray ident = packet2ident(packet);
				if(ident.length()){
					packetProcess(packet,ident,now);
					packets++;
				}
			}
		} else {
//            qInfo() << "No input";
		}
		if(elapsed.elapsed() > (10000) && stats){
			qInfo() << "Queue:" << queue.count() << "Packets:" << packets;
			elapsed.restart();
		}
		if(ctrl_c){
			tshark.terminate();
			tshark.waitForFinished();
			break;
		}
	}
	if(printUnknown){
		QStringList sf;
		foreach(QString s, skippedFields.keys()){
			sf << s;
		}
		sf.sort();
		foreach(QString s, sf){
			qInfo() << s << ", " << skippedFields.value(s);
		}
	}
	flushQueue();
	return(0);
}
