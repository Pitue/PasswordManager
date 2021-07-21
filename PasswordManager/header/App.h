#ifndef __PWMNGER_APP_H__
#define __PWMNGER_APP_H__

#include "common.h"

class App :
    public wxApp {

public:
  App();
  ~App();

  bool OnInit() override;
};

wxIMPLEMENT_APP(App);

#endif