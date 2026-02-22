import { ComponentFixture, TestBed } from '@angular/core/testing';

import { FileEncryption } from './file-encryption';

describe('FileEncryption', () => {
  let component: FileEncryption;
  let fixture: ComponentFixture<FileEncryption>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [FileEncryption]
    })
    .compileComponents();

    fixture = TestBed.createComponent(FileEncryption);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
