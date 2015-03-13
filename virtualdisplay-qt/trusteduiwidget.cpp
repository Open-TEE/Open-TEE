#include "trusteduiwidget.hpp"
#include "tuistate.hpp"
#include "comprotocolmessage.hpp"

#include <iostream>

TrustedUIWidget::TrustedUIWidget(QWidget *parent) :
	QWidget(parent),
	state_(new TUIState),
	socket_(),
	service_(state_)
{
	// Connect Socket to Service
	connect(&socket_,
		SIGNAL(messageReceived(const ComProtocolMessage &)),
		&service_,
		SLOT(messageReceived(const ComProtocolMessage &)));
	connect(&service_,
		SIGNAL(sendMessage(const ComProtocolMessage &)),
		&socket_,
		SLOT(sendMessage(const ComProtocolMessage &)));
}

TrustedUIWidget::~TrustedUIWidget()
{
}

void TrustedUIWidget::changeColor()
{
	// Set widget background color blue
	QPalette pal(palette());
	pal.setColor(QPalette::Background,
		     QColor(rand() % 255,
			    rand() % 255,
			    rand() % 255));
	this->setAutoFillBackground(true);
	this->setPalette(pal);
	this->show();
}

bool TrustedUIWidget::start()
{
	const bool success = socket_.start();

	if (success)
		emit statusMessage("Connected to socket");
	else
		emit statusMessage("Error connecting to socket");

	// Send initialization message
	sendDisplayInitMsg();

	return success;
}

void TrustedUIWidget::stop()
{
	socket_.stop();
}

void TrustedUIWidget::sendDisplayInitMsg()
{
/*
struct com_msg_tui_display_init {
	struct com_msg_hdr msg_hdr;
	uint32_t timeout;
	uint32_t grayscaleBitsDepth;
	uint32_t redBitsDepth;
	uint32_t greenBitsDepth;
	uint32_t blueBitsDepth;
	uint32_t widthInch;
	uint32_t heightInch;
	uint32_t maxEntryFields;
	uint32_t entryFieldLabelWidth;
	uint32_t entryFieldLabelHeight;
	uint32_t maxEntryFieldLength;
	uint8_t labelColorRed;
	uint8_t labelColorGreen;
	uint8_t labelColorBlue;
	uint32_t labelWidth;
	uint32_t labelHeight;
	struct {
		uint32_t textLength;
		uint32_t buttonWidth;
		uint32_t buttonHeight;
		uint32_t buttonTextCustom;
		uint32_t buttonImageCustom;
	} buttonInfo[6];
} __attribute__((aligned));
*/
	QString btnText("TESTI");
	QByteArray textArray(btnText.toUtf8());

	com_msg_tui_display_init init_msg {
		com_msg_hdr {
			0,
			COM_MSG_NAME_TUI_DISPLAY_INIT,
			COM_TYPE_QUERY
		},
		5000, // timeout
		8, // grayscaleBitsDepth
		8, // redBitsDepth
		8, // greenBitsDepth
		8, // blueBitsDepth
		150, // widthInch
		150, // heightInch
		4, // maxEntryFields
		720, // entryFieldLabelWidth
		50, // entryFieldLabelHeight
		256, // maxEntryFieldLength
		0, // labelColorRed
		0, // labelColorGreen
		0, // labelColorBlue
		720, // labelWidth
		200, // labelHeight
		{
			{5, 100, 200, true, true},
			{5, 100, 200, true, true},
			{5, 100, 200, true, true},
			{5, 100, 200, true, true},
			{5, 100, 200, true, true},
			{5, 100, 200, true, true},
		}
	};

	QByteArray raw_msg(reinterpret_cast <char *> (&init_msg),
			   static_cast <int> (sizeof(init_msg)));

	for (unsigned int i = 0; i < 6; ++i) {
		raw_msg.append("TESTI\0", 6);
	}

	ComProtocolMessage com_msg(raw_msg);
	socket_.sendMessage(com_msg);
}
