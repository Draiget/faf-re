#pragma once

namespace moho
{
    template<class T>
    class TDatListItem
    {
        using type = T;

        TDatListItem<type>* prev;
        TDatListItem<type>* next;

        TDatListItem() :
            prev{ this },
            next{ this }
        {
        }

        ~TDatListItem() {
            this->ListUnlink();
        }

        void ListUnlink() {
            this->prev->next = this->next;
            this->next->prev = this->prev;
            this->next = this;
            this->prev = this;
        }

        void ListLinkBefore(TDatListItem<type>* item) {
            this->prev = item->prev;
            this->next = item;
            item->prev = this;
            this->prev->next = this;
        }

        void ListLinkAfter(TDatListItem<type>* item) {
            this->prev = item;
            this->next = item->next;
            item->next->prev = this;
            this->prev->next = this;
        }

        bool ListEmpty() {
            return this->next == this;
        }

        type* ListGetNext() {
            return static_cast<type*>(this->next);
        }

        type* ListGetPrev() {
            return static_cast<type*>(this->prev);
        }
    };
}