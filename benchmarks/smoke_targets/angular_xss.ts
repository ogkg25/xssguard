import { Component, SecurityContext } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Component({
  selector: 'app-root',
  template: '<div [innerHTML]="dangerousUrl"></div>',
})
export class AppComponent {
  dangerousUrl: any;

  constructor(private sanitizer: DomSanitizer) {
    // RULE: Angular bypassSecurityTrust*
    this.dangerousUrl = this.sanitizer.bypassSecurityTrustHtml(
      '<script>alert("XSS")</script>'
    );
  }
}
