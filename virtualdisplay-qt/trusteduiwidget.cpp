#include "trusteduiwidget.hpp"
#include "tuistate.hpp"
#include "comprotocolmessage.hpp"

#include <iostream>
#include <QPushButton>

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

	// TODO: HACK
	connect(&service_,
		SIGNAL(displayScreen(TUIProtocol::DisplayScreenRequest)),
		this,
		SLOT(displayScreen(TUIProtocol::DisplayScreenRequest)));

	setLayout(&layout_);
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

void TrustedUIWidget::displayScreen(TUIProtocol::DisplayScreenRequest req)
{
	cleanupScreen();

	layout_.addRow("", new QLabel(req.screenConfiguration().screenLabel().text().c_str()));

	for (auto ef : req.entryFields()) {
		QLineEdit* new_line_edit = new QLineEdit();

		switch (ef.mode()) {
			case TEE_TUI_HIDDEN_MODE:
				new_line_edit->setEchoMode(QLineEdit::Password);
				break;
			case TEE_TUI_TEMPORARY_CLEAR_MODE:
				new_line_edit->setEchoMode(QLineEdit::PasswordEchoOnEdit);
				break;
			case TEE_TUI_CLEAR_MODE:
			default:
				new_line_edit->setEchoMode(QLineEdit::Normal);
				break;
		}

		layout_.addRow(ef.label().c_str(), new_line_edit);
		layout_widgets_.push_back(new_line_edit);
	}

	QPushButton *btn = new QPushButton("OK");

	connect(btn,
		SIGNAL(clicked()),
		this,
		SLOT(respond()));

	layout_.addRow("", btn);
}

void TrustedUIWidget::cleanupScreen()
{
	QLayoutItem *child;
	while (layout_.count() != 0) {
	        child = layout_.takeAt(0);
		delete child->widget();
		delete child;
	}
	/*
	for (auto entry : layout_widgets_) {
		layout_.removeWidget(entry);
	}
	*/

	layout_widgets_.clear();
}

void TrustedUIWidget::respond()
{
	// Serialize response
	TUIProtocol::DisplayScreenResponse resp;

	resp.ret() = 1;

	for (auto entry : layout_widgets_) {
		resp.entryFieldInput().push_back(entry->text().toStdString());
	}

	cleanupScreen();

	QByteArray response;
	msgpack_pack(response, resp);

	//Q_ASSERT(req.entryFields().size() == resp.entryFieldInput().size());

	ComProtocolMessage respo(COM_MSG_NAME_TUI_DISPLAY_SCREEN,
			         COM_TYPE_RESPONSE,
			         0,
			         response);

	socket_.sendMessage(respo);
}
