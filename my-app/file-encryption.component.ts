import { Component } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Component({
  selector: 'app-file-encryption',
  templateUrl: './file-encryption.component.html',
  styleUrls: ['./file-encryption.component.css']
})
export class FileEncryptionComponent {
  selectedFile: File | null = null;
  operation: string = 'encrypt';
  key: string = '';
  response: any = {};
  message: string = '';

  constructor(private http: HttpClient) {}

  onFileSelected(event: any) {
    this.selectedFile = event.target.files[0];
  }

  processFile() {
    if (!this.selectedFile) {
      alert('Please choose a file.');
      return;
    }

    const formData = new FormData();
    formData.append('file', this.selectedFile);
    formData.append('operation', this.operation);
    if (this.key) formData.append('key', this.key);

    this.http.post('http://localhost:5000/file/process', formData)
      .subscribe({
        next: (res: any) => {
          this.response = res;
          this.message = res.message;
        },
        error: (err) => {
          this.message = err.error?.error || 'Something went wrong.';
        }
      });
  }
}
